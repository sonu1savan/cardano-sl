{-# LANGUAGE RankNTypes   #-}
{-# LANGUAGE TypeFamilies #-}

-- | Sum of slotting implementations.

module Pos.Slotting.Impl.Sum
       ( SlottingContextSum (..)

       , MonadSlottingSum
       , askSlottingContextSum
       , getCurrentSlotSum
       , getCurrentSlotBlockingSum
       , getCurrentSlotInaccurateSum
       , currentTimeSlottingSum

       -- * Workers
       , SlottingWorkerModeSum
       , slottingWorkers
       ) where

import           Universum

import           Ether.Internal           (HasLens (..))

import           Pos.Core.Types           (SlotId (..), Timestamp)
import           Pos.Slotting.Impl.Ntp    (NtpMode, NtpSlottingVar, NtpWorkerMode,
                                           ntpCurrentTime, ntpGetCurrentSlot,
                                           ntpGetCurrentSlotBlocking,
                                           ntpGetCurrentSlotInaccurate, ntpWorkers)
import           Pos.Slotting.Impl.Simple (SimpleSlottingMode, SimpleSlottingVar,
                                           currentTimeSlottingSimple,
                                           getCurrentSlotBlockingSimple,
                                           getCurrentSlotInaccurateSimple,
                                           getCurrentSlotSimple)

-- | Sum of all contexts used by slotting implementations.
data SlottingContextSum
    = SCSimple SimpleSlottingVar
    | SCNtp NtpSlottingVar

-- | Monad which combines all 'MonadSlots' implementations (and
-- uses only one of them).
type MonadSlottingSum ctx m =
    ( MonadReader ctx m
    , HasLens SlottingContextSum ctx SlottingContextSum
    )

askSlottingContextSum :: MonadSlottingSum ctx m => m SlottingContextSum
askSlottingContextSum = view (lensOf @SlottingContextSum)

type SlotsSumEnv ctx m =
    ( MonadSlottingSum ctx m
    , NtpMode m
    -- ^ Contains @MonadThrow@
    , SimpleSlottingMode m
    )

getCurrentSlotSum :: (SlotsSumEnv ctx m) => m (Maybe SlotId)
getCurrentSlotSum =
    view (lensOf @SlottingContextSum) >>= \case
        SCSimple var -> getCurrentSlotSimple var
        SCNtp var    -> ntpGetCurrentSlot var

getCurrentSlotBlockingSum :: (SlotsSumEnv ctx m) => m SlotId
getCurrentSlotBlockingSum =
    view (lensOf @SlottingContextSum) >>= \case
        SCSimple var -> getCurrentSlotBlockingSimple var
        SCNtp var -> ntpGetCurrentSlotBlocking var

getCurrentSlotInaccurateSum :: (SlotsSumEnv ctx m) => m SlotId
getCurrentSlotInaccurateSum =
    view (lensOf @SlottingContextSum) >>= \case
        SCSimple var -> getCurrentSlotInaccurateSimple var
        SCNtp var -> ntpGetCurrentSlotInaccurate var

currentTimeSlottingSum :: SlotsSumEnv ctx m => m Timestamp
currentTimeSlottingSum =
    view (lensOf @SlottingContextSum) >>= \case
        SCSimple _ -> currentTimeSlottingSimple
        SCNtp var  -> ntpCurrentTime var

type SlottingWorkerModeSum m = NtpWorkerMode m

-- | Get all slotting workers using 'SlottingContextSum'.
slottingWorkers :: SlottingWorkerModeSum m => SlottingContextSum -> [m ()]
slottingWorkers (SCSimple _) = []
slottingWorkers (SCNtp var)  = ntpWorkers var
