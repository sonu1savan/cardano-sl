{-# LANGUAGE CPP                 #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Runners in various modes.

module Pos.Launcher.Runner
       ( -- * High level runners
         runRealMode
       , runRealBasedMode

       -- * Exported for custom usage in CLI utils
       , runServer
       ) where

import           Universum                       hiding (bracket)

import           Control.Monad.Fix               (MonadFix)
import qualified Control.Monad.Reader            as Mtl
import qualified Data.Map                        as M
import           Formatting                      (build, sformat, (%))
import           Mockable                        (MonadMockable, Production (..), bracket,
                                                  killThread)
import           Node                            (Node, NodeAction (..), NodeEndPoint,
                                                  ReceiveDelay, Statistics,
                                                  defaultNodeEnvironment,
                                                  hoistSendActions, noReceiveDelay, node,
                                                  simpleNodeEndPoint)
import           Node.Conversation               (Converse)
import           Node.OutboundQueue              (OutboundQueue)
import           Network.Broadcast.OutboundQueue as OQ
import           Node.Util.Monitor               (setupMonitor, stopMonitor)
import qualified System.Metrics                  as Metrics
import           System.Random                   (newStdGen)
import qualified System.Remote.Monitoring        as Monitoring
import qualified System.Remote.Monitoring.Statsd as Monitoring
import           System.Wlog                     (WithLogger, logInfo)

import           Pos.Binary                      ()
import           Pos.Communication               (ActionSpec (..), BiP (..), InSpecs (..),
                                                  MkListeners (..), OutSpecs (..),
                                                  VerInfo (..), allListeners,
                                                  hoistMkListeners, NodeId, NodeType (..),
                                                  MsgType (..), Msg (..), PackingType,
                                                  PeerData)
import qualified Pos.Constants                   as Const
import           Pos.Context                     (NodeContext (..))
import           Pos.DHT.Real                    (foreverRejoinNetwork)
import           Pos.Discovery                   (DiscoveryContextSum (..))
import           Pos.Launcher.Param              (BaseParams (..), LoggingParams (..),
                                                  NodeParams (..))
import           Pos.Launcher.Resource           (NodeResources (..), hoistNodeResources)
import           Pos.Network.Types               (NetworkConfig (..), NodeName)
import           Pos.Security                    (SecurityWorkersClass)
import           Pos.Ssc.Class                   (SscConstraint)
import           Pos.Statistics                  (EkgParams (..), StatsdParams (..))
import           Pos.Util.JsonLog                (JsonLogConfig (..),
                                                  jsonLogConfigFromHandle)
import           Pos.WorkMode                    (RealMode, RealModeContext (..),
                                                  WorkMode)

----------------------------------------------------------------------------
-- High level runners
----------------------------------------------------------------------------

-- | Run activity in 'RealMode'.
runRealMode
    :: forall ssc a.
       (SscConstraint ssc, SecurityWorkersClass ssc)
    => NodeResources ssc (RealMode ssc)
    -> (ActionSpec (RealMode ssc) a, OutSpecs)
    -> Production a
runRealMode = runRealBasedMode identity identity

-- | Run activity in something convertible to 'RealMode' and back.
runRealBasedMode
    :: forall ssc ctx m a.
       (SscConstraint ssc, SecurityWorkersClass ssc, WorkMode ssc ctx m)
    => (forall b. m b -> RealMode ssc b)
    -> (forall b. RealMode ssc b -> m b)
    -> NodeResources ssc m
    -> (ActionSpec m a, OutSpecs)
    -> Production a
runRealBasedMode unwrap wrap nr@NodeResources {..} (ActionSpec action, outSpecs) =
    runRealModeDo (hoistNodeResources unwrap nr) listeners outSpecs $
    ActionSpec $ \vI sendActions ->
        unwrap . action vI $ hoistSendActions wrap unwrap sendActions
  where
    listeners = hoistMkListeners unwrap wrap allListeners

-- | RealMode runner.
runRealModeDo
    :: forall ssc a.
       (SscConstraint ssc, SecurityWorkersClass ssc)
    => NodeResources ssc (RealMode ssc)
    -> MkListeners (RealMode ssc)
    -> OutSpecs
    -> ActionSpec (RealMode ssc) a
    -> Production a
runRealModeDo NodeResources {..} listeners outSpecs action =
    specialDiscoveryWrapper $ do
        jsonLogConfig <- maybe
            (pure JsonLogDisabled)
            jsonLogConfigFromHandle
            nrJLogHandle

        (oq, mkOq) <- initQueue ncNetworkConfig ncSelfName

        runToProd jsonLogConfig oq $
          runServer ncNetworkConfig
                    (simpleNodeEndPoint nrTransport)
                    (const noReceiveDelay)
                    listeners
                    outSpecs
                    (startMonitoring oq)
                    stopMonitoring
                    mkOq
                    action
  where
    NodeContext {..} = nrContext
    NodeParams {..} = ncNodeParams
    LoggingParams {..} = bpLoggingParams npBaseParams
    startMonitoring oq node' =
        case npEnableMetrics of
            False -> return Nothing
            True  -> Just <$> do
                ekgStore' <- setupMonitor
                    (runProduction . runToProd JsonLogDisabled oq) node' nrEkgStore
                liftIO $ Metrics.registerGcMetrics ekgStore'
                mEkgServer <- case npEkgParams of
                    Nothing -> return Nothing
                    Just (EkgParams {..}) -> Just <$> do
                        liftIO $ Monitoring.forkServerWith ekgStore' ekgHost ekgPort
                mStatsdServer <- case npStatsdParams of
                    Nothing -> return Nothing
                    Just (StatsdParams {..}) -> Just <$> do
                        let statsdOptions = Monitoring.defaultStatsdOptions
                                { Monitoring.host = statsdHost
                                , Monitoring.port = statsdPort
                                , Monitoring.flushInterval = statsdInterval
                                , Monitoring.debug = statsdDebug
                                , Monitoring.prefix = statsdPrefix
                                , Monitoring.suffix = statsdSuffix
                                }
                        liftIO $ Monitoring.forkStatsd statsdOptions ekgStore'
                return (mEkgServer, mStatsdServer)

    stopMonitoring Nothing = return ()
    stopMonitoring (Just (mEkg, mStatsd)) = do
        whenJust mStatsd (killThread . Monitoring.statsdThreadId)
        whenJust mEkg stopMonitor

    -- TODO: it would be good to put this behavior into 'Discovery' class.
    -- TODO: there's really no reason why we have to continually rejoin the
    -- network. In fact it runs contrary to the intended use of Kademlia.
    -- Joining a network which you've already joined *should* give an ID
    -- clash with high probability (the initial peer probably remembers you),
    -- but we've actually modified the Kademlia library to ignore this
    -- just because we abuse it here in cardano-sl.
    specialDiscoveryWrapper = case ncDiscoveryContext of
        DCStatic _          -> identity
        DCKademlia kademlia -> foreverRejoinNetwork kademlia

    runToProd :: forall t .
                 JsonLogConfig
              -> OQ (RealMode ssc)
              -> RealMode ssc t
              -> Production t
    runToProd jlConf oq act = Mtl.runReaderT act $
        RealModeContext
            nrDBs
            nrSscState
            nrTxpState
            nrDlgState
            nrPeerState
            jlConf
            lpRunnerTag
            nrContext
            oq

type OQ m =
    OutboundQ (ClassifiedConversation PeerData PackingType NodeId m) NodeId

newtype MkOq m = MkOq (
       Converse PackingType PeerData m
    -> m (OutboundQueue PackingType PeerData NodeId Msg m)
  )

initQueue
    :: (MonadIO m, MonadIO m', MonadMockable m', WithLogger m')
    => NetworkConfig NodeId
    -> NodeName
    -> m (OQ m', MkOq m')
initQueue NetworkConfig{..} selfName = do
    oq <- OQ.new selfName enqueuePolicy dequeuePolicy failurePolicy
    return (oq, MkOq $ OQ.asOutboundQueue oq identity getNodeType getMsgType getMsgOrigin)
  where
    ourNodeType = ncNodeType
    enqueuePolicy = OQ.defaultEnqueuePolicy ourNodeType
    dequeuePolicy = OQ.defaultDequeuePolicy ourNodeType
    failurePolicy = OQ.defaultFailurePolicy ourNodeType

    -- TODO verify that the NodeId is normalized: if we use a numeric
    -- address, but the peer uses a DNS name, we'll still correctly identify
    -- it.
    getNodeType :: NodeId -> NodeType
    getNodeType nid = case M.lookup nid ncClassification of
        -- If we don't know of this peer then we assume it's an edge node.
        Nothing -> NodeEdge
        Just (ty, _) -> ty

    getMsgType :: Msg -> MsgType
    getMsgType (Msg (ty, _)) = ty

    getMsgOrigin :: Msg -> Origin NodeId
    getMsgOrigin (Msg (_, origin)) = origin

runServer
    :: forall m t b .
       (MonadIO m, MonadMockable m, MonadFix m, WithLogger m)
    => NetworkConfig NodeId
    -> (m (Statistics m) -> NodeEndPoint m)
    -> (m (Statistics m) -> ReceiveDelay m)
    -> MkListeners m
    -> OutSpecs
    -> (Node m -> m t)
    -> (t -> m ())
    -> MkOq m
    -> ActionSpec m b
    -> m b
runServer NetworkConfig {..} mkTransport mkReceiveDelay mkL (OutSpecs wouts) withNode afterNode (MkOq mkOq) (ActionSpec action) = do
    stdGen <- liftIO newStdGen
    logInfo $ sformat ("Our verInfo: "%build) ourVerInfo
    node mkTransport mkReceiveDelay mkConnectDelay mkOq stdGen BiP ourVerInfo defaultNodeEnvironment $ \__node ->
        NodeAction mkListeners' $ \sendActions ->
            bracket (withNode __node) afterNode (const (action ourVerInfo sendActions))
  where
    mkConnectDelay = const (pure Nothing)
    InSpecs ins = inSpecs mkL
    OutSpecs outs = outSpecs mkL
    ourVerInfo =
        VerInfo Const.protocolMagic Const.lastKnownBlockVersion ins $ outs <> wouts
    mkListeners' theirVerInfo =
        mkListeners mkL ourVerInfo theirVerInfo
