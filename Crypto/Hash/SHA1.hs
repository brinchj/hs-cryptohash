{-# LANGUAGE ForeignFunctionInterface, CPP, MultiParamTypeClasses #-}

-- |
-- Module      : Crypto.Hash.SHA1
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing SHA1 bindings
--
module Crypto.Hash.SHA1
	( Ctx(..)
	, SHA1

	-- * Incremental hashing Functions
	, init     -- :: Ctx
	, update   -- :: Ctx -> ByteString -> Ctx
	, finalize -- :: Ctx -> ByteString

	-- * Single Pass hashing
	, hash     -- :: ByteString -> ByteString
	, hashlazy -- :: ByteString -> ByteString
	) where

import Prelude hiding (init)
import Foreign
import Foreign.C.String
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCString, unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, memcpy)

import qualified Crypto.Hash.Util as Util

#ifdef HAVE_CRYPTOAPI

import Control.Monad (liftM)
import Data.Serialize (Serialize(..))
import Data.Serialize.Get (getByteString)
import Data.Serialize.Put (putByteString)
import Data.Tagged (Tagged(..))
import qualified Crypto.Classes as C (Hash(..))

instance C.Hash Ctx SHA1 where
	outputLength    = Tagged (20 * 8)
	blockLength     = Tagged (64 * 8)
	initialCtx      = init
	updateCtx       = update
	finalize ctx bs = Digest . finalize $ update ctx bs

instance Serialize SHA1 where
	get            = liftM Digest (getByteString digestSize)
	put (Digest d) = putByteString d

#endif

data Ctx = Ctx !ByteString
data SHA1 = Digest !ByteString
	deriving (Show)

-- Constant time Eq and Compare instances
instance Eq SHA1 where
  (Digest a) == (Digest b) = a `Util.constTimeEq` b

instance Ord SHA1 where
  (Digest a) `compare` (Digest b) = a `Util.constTimeCompare` b


digestSize, sizeCtx :: Int
digestSize = 20
sizeCtx = 96

instance Storable Ctx where
	sizeOf _    = sizeCtx
	alignment _ = 16
	poke ptr (Ctx b) = unsafeUseAsCString b (\cs -> memcpy (castPtr ptr) (castPtr cs) (fromIntegral sizeCtx))

	peek ptr = create sizeCtx (\bptr -> memcpy bptr (castPtr ptr) (fromIntegral sizeCtx)) >>= return . Ctx

foreign import ccall unsafe "sha1.h sha1_init"
	c_sha1_init :: Ptr Ctx -> IO ()

foreign import ccall "sha1.h sha1_update"
	c_sha1_update :: Ptr Ctx -> CString -> Word32 -> IO ()

foreign import ccall unsafe "sha1.h sha1_finalize"
	c_sha1_finalize :: Ptr Ctx -> CString -> IO ()

allocInternal :: (Ptr Ctx -> IO a) -> IO a
allocInternal = alloca

allocInternalFrom :: Ctx -> (Ptr Ctx -> IO a) -> IO a
allocInternalFrom ctx f = allocInternal $ \ptr -> (poke ptr ctx >> f ptr)

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
	unsafeUseAsCStringLen d (\(cs, len) -> c_sha1_update ptr cs (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr =
	allocaBytes digestSize (\cs -> c_sha1_finalize ptr cs >> B.packCStringLen (cs, digestSize))

{-# NOINLINE init #-}
-- | init a context
init :: Ctx
init = unsafePerformIO $ allocInternal $ \ptr -> do (c_sha1_init ptr >> peek ptr)

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d = unsafePerformIO $ allocInternalFrom ctx $ \ptr -> do updateInternalIO ptr d >> peek ptr

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: Ctx -> ByteString
finalize ctx = unsafePerformIO $ allocInternalFrom ctx $ \ptr -> do finalizeInternalIO ptr

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: ByteString -> ByteString
hash d = unsafePerformIO $ allocInternal $ \ptr -> do
	c_sha1_init ptr >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: L.ByteString -> ByteString
hashlazy l = unsafePerformIO $ allocInternal $ \ptr -> do
	c_sha1_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
