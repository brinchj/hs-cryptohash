module Crypto.Hash.Util (
    constTimeEq
  , constTimeCompare
  ) where

import qualified Data.ByteString as B
import qualified Data.Serialize as S

import Data.Bits ((.|.), (.&.), xor)
import Data.List (foldl')
import Data.Word


-- Constant time equallity
constTimeCompare :: B.ByteString -> B.ByteString -> Ordering
constTimeCompare s1 s2
  | B.length s1 /= B.length s2 = error "Data size mismatch (hashes of different length?)"
  | otherwise =
    toEnum $ fromIntegral $ 1 - (ilessBS s1 s2) + (ilessBS s2 s1)
  where
    -- less on bytestrings
    ilessBS bs0 bs1 =
      foldl' ilessBSGo 0 $ B.zip (B.reverse bs0) (B.reverse bs1)
    ilessBSGo res (a, b) =
      (res .&. ieqByte a b) .|. ilessByte a b
    -- less and eq on words
    ilessByte a b
      | a < b = 1 :: Word8
      | otherwise = 0
    ieqByte a b
      | a == b = 1 :: Word8
      | otherwise = 0


-- Politely borrowed from Thomas DuBuisson's crypto-api package:
-- | Checks two bytestrings for equality without breaches for
-- timing attacks.
--
-- Semantically, @constTimeEq = (==)@.  However, @x == y@ takes less
-- time when the first byte is different than when the first byte
-- is equal.  This side channel allows an attacker to mount a
-- timing attack.  On the other hand, @constTimeEq@ always takes the
-- same time regardless of the bytestrings' contents.
--
-- You should always use @constTimeEq@ when comparing hashes,
-- otherwise you may leave a significant security hole
-- (cf. <http://codahale.com/a-lesson-in-timing-attacks/>).
constTimeEq :: B.ByteString -> B.ByteString -> Bool
constTimeEq s1 s2
  | B.length s1 /= B.length s2 = error "Data size mismatch (hashes of different length?)"
  | otherwise =
    foldl' (.|.) 0 (B.zipWith xor s1 s2) == 0
