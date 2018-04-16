{-# LANGUAGE DataKinds    #-}
{-# LANGUAGE PolyKinds    #-}
{-# LANGUAGE TypeFamilies #-}

module Pos.Client.KeyStorage
    ( MonadKeysRead (..)
    , MonadKeys (..)
    , KeyData
    , KeyError (..)
    , AllUserSecrets (..)
    , AllUserPublics (..)
    , getSecretDefault
    , modifySecretPureDefault
    , modifySecretDefault
    , getPrimaryKey
    , getSecretKeys
    , getPublicKeys
    , getSecretKeysPlain
    , getPublicKeysPlain
    , addSecretKey
    , addPublicKey
    , deleteAllSecretKeys
    , deleteAllPublicKeys
    , deleteSecretKeyBy
    , deletePublicKeyBy
    , newSecretKey
    , keyDataFromFile
    , publicKeyDataFromFile
    ) where

import           Universum

import qualified Control.Concurrent.STM as STM
import           Control.Lens ((<%=), (<>~))
import           Serokell.Util (modifyTVarS)
import           System.Wlog (WithLogger)

import           Pos.Binary.Crypto ()
import           Pos.Crypto (EncryptedSecretKey, PassPhrase, SecretKey, PublicKey,
                             hash, runSecureRandom, safeKeyGen)
import           Pos.Util.UserSecret (HasUserSecret (..), UserSecret, peekUserSecret, usKeys,
                                      usPrimKey, writeUserSecret)
import           Pos.Util.UserPublic (HasUserPublic (..), UserPublic, peekUserPublic, upKeys)

type KeyData = TVar UserSecret
type PublicKeyData = TVar UserPublic

----------------------------------------------------------------------
-- MonadKeys class and default functions
----------------------------------------------------------------------

class Monad m => MonadKeysRead m where
    getSecret :: m UserSecret
    getPublic :: m UserPublic

class MonadKeysRead m => MonadKeys m where
    modifySecret :: (UserSecret -> UserSecret) -> m ()
    modifyPublic :: (UserPublic -> UserPublic) -> m ()

type HasKeysContext ctx m =
    ( MonadReader ctx m
    , HasUserSecret ctx
    , MonadIO m
    )

getSecretDefault :: HasKeysContext ctx m => m UserSecret
getSecretDefault = view userSecret >>= atomically . STM.readTVar

modifySecretPureDefault :: HasKeysContext ctx m => (UserSecret -> UserSecret) -> m ()
modifySecretPureDefault f = do
    us <- view userSecret
    void $ atomically $ modifyTVarS us (identity <%= f)

modifySecretDefault :: HasKeysContext ctx m => (UserSecret -> UserSecret) -> m ()
modifySecretDefault f = do
    us <- view userSecret
    new <- atomically $ modifyTVarS us (identity <%= f)
    writeUserSecret new

----------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------

getPrimaryKey :: MonadKeysRead m => m (Maybe SecretKey)
getPrimaryKey = view usPrimKey <$> getSecret

newtype AllUserSecrets = AllUserSecrets
    { getAllUserSecrets :: [EncryptedSecretKey]
    } deriving (ToList, Container)

newtype AllUserPublics = AllUserPublics
    { getAllUserPublics :: [PublicKey]
    } deriving (ToList, Container)

type instance Element AllUserSecrets = EncryptedSecretKey
type instance Element AllUserPublics = PublicKey

getSecretKeys :: MonadKeysRead m => m AllUserSecrets
getSecretKeys = AllUserSecrets . view usKeys <$> getSecret

getPublicKeys :: MonadKeysRead m => m AllUserPublics
getPublicKeys = AllUserPublics . view upKeys <$> getPublic

getSecretKeysPlain :: MonadKeysRead m => m [EncryptedSecretKey]
getSecretKeysPlain = view usKeys <$> getSecret

getPublicKeysPlain :: MonadKeysRead m => m [PublicKey]
getPublicKeysPlain = view upKeys <$> getPublic

addSecretKey :: MonadKeys m => EncryptedSecretKey -> m ()
addSecretKey sk = modifySecret $ \us ->
    if view usKeys us `containsKey` sk
    then us
    else us & usKeys <>~ [sk]

addPublicKey :: MonadKeys m => PublicKey -> m ()
addPublicKey pk = modifyPublic $ \up ->
    if view upKeys up `containsPublicKey` pk
    then up
    else up & upKeys <>~ [pk]

deleteAllSecretKeys :: MonadKeys m => m ()
deleteAllSecretKeys = modifySecret (usKeys .~ [])

deleteAllPublicKeys :: MonadKeys m => m ()
deleteAllPublicKeys = modifyPublic (upKeys .~ [])

deleteSecretKeyBy :: MonadKeys m => (EncryptedSecretKey -> Bool) -> m ()
deleteSecretKeyBy predicate = modifySecret (usKeys %~ filter (not . predicate))

deletePublicKeyBy :: MonadKeys m => (PublicKey -> Bool) -> m ()
deletePublicKeyBy predicate = modifyPublic (upKeys %~ filter (not . predicate))

-- | Helper for generating a new secret key
newSecretKey :: (MonadIO m, MonadKeys m) => PassPhrase -> m EncryptedSecretKey
newSecretKey pp = do
    (_, sk) <- liftIO $ runSecureRandom $ safeKeyGen pp
    addSecretKey sk
    pure sk

------------------------------------------------------------------------
-- Common functions
------------------------------------------------------------------------

containsKey :: [EncryptedSecretKey] -> EncryptedSecretKey -> Bool
containsKey ls k = hash k `elem` map hash ls

containsPublicKey :: [PublicKey] -> PublicKey -> Bool
containsPublicKey = flip elem

keyDataFromFile :: (MonadIO m, WithLogger m) => FilePath -> m KeyData
keyDataFromFile fp = peekUserSecret fp >>= liftIO . STM.newTVarIO

publicKeyDataFromFile :: (MonadIO m, WithLogger m) => FilePath -> m PublicKeyData
publicKeyDataFromFile fp = peekUserPublic fp >>= liftIO . STM.newTVarIO

data KeyError =
    PrimaryKey !Text -- ^ Failed attempt to delete primary key
    deriving (Show)

instance Exception KeyError
