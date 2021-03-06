import Test.HUnit
import Data.Char
import Data.Bits
import Data.Word
import qualified Data.ByteString as B
import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD4 as MD4
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA384 as SHA384
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.SHA512t as SHA512t
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Hash.Tiger as Tiger
import qualified Crypto.Hash.Skein256 as Skein256
import qualified Crypto.Hash.Skein512 as Skein512

v0 = ""
v1 = "The quick brown fox jumps over the lazy dog"
v2 = "The quick brown fox jumps over the lazy cog"
vectors = [ v0, v1, v2 ]

data HashFct = HashFct
	{ fctHash   :: (B.ByteString -> B.ByteString)
	, fctInc    :: ([B.ByteString] -> B.ByteString) }

hashinc i u f = f . foldl u i

md2Hash    = HashFct { fctHash = MD2.hash, fctInc = hashinc MD2.init MD2.update MD2.finalize }
md4Hash    = HashFct { fctHash = MD4.hash, fctInc = hashinc MD4.init MD4.update MD4.finalize }
md5Hash    = HashFct { fctHash = MD5.hash, fctInc = hashinc MD5.init MD5.update MD5.finalize }

sha1Hash   = HashFct { fctHash = SHA1.hash, fctInc = hashinc SHA1.init SHA1.update SHA1.finalize }

sha224Hash = HashFct { fctHash = SHA224.hash, fctInc = hashinc SHA224.init SHA224.update SHA224.finalize }
sha256Hash = HashFct { fctHash = SHA256.hash, fctInc = hashinc SHA256.init SHA256.update SHA256.finalize }

sha384Hash = HashFct { fctHash = SHA384.hash, fctInc = hashinc SHA384.init SHA384.update SHA384.finalize }
sha512Hash = HashFct { fctHash = SHA512.hash, fctInc = hashinc SHA512.init SHA512.update SHA512.finalize }
sha512_224Hash = HashFct { fctHash = SHA512t.hash 224, fctInc = hashinc (SHA512t.init 224) SHA512t.update SHA512t.finalize }
sha512_256Hash = HashFct { fctHash = SHA512t.hash 256, fctInc = hashinc (SHA512t.init 256) SHA512t.update SHA512t.finalize }

ripemd160Hash = HashFct { fctHash = RIPEMD160.hash, fctInc = hashinc RIPEMD160.init RIPEMD160.update RIPEMD160.finalize }
tigerHash = HashFct { fctHash = Tiger.hash, fctInc = hashinc Tiger.init Tiger.update Tiger.finalize }

skein256Hash x = HashFct { fctHash = Skein256.hash x, fctInc = hashinc (Skein256.init x) Skein256.update Skein256.finalize }
skein512Hash x = HashFct { fctHash = Skein512.hash x, fctInc = hashinc (Skein512.init x) Skein512.update Skein512.finalize }

results :: [ (String, HashFct, [String]) ]
results = [
	("MD2", md2Hash, [
		"8350e5a3e24c153df2275c9f80692773",
		"03d85a0d629d2c442e987525319fc471",
		"6b890c9292668cdbbfda00a4ebf31f05" ]),
	("MD4", md4Hash, [
		"31d6cfe0d16ae931b73c59d7e0c089c0",
		"1bee69a46ba811185c194762abaeae90",
		"b86e130ce7028da59e672d56ad0113df" ]),
	("MD5", md5Hash, [
		"d41d8cd98f00b204e9800998ecf8427e",
		"9e107d9d372bb6826bd81d3542a419d6",
		"1055d3e698d289f2af8663725127bd4b" ]),
	("SHA1", sha1Hash, [
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
		"de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" ]),
	("SHA224", sha224Hash, [
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		"730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
		"fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b" ]),
	("SHA256", sha256Hash, [
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		"e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be" ]),
	("SHA384", sha384Hash, [
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
		"098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b" ]),
	("SHA512", sha512Hash, [
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
		"3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045" ]),

	("SHA512/224", sha512_224Hash, [
		"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
		"944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37",
		"2b9d6565a7e40f780ba8ab7c8dcf41e3ed3b77997f4c55aa987eede5" ]),
	("SHA512/256", sha512_256Hash, [
		"c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
		"dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
		"cc8d255a7f2f38fd50388fd1f65ea7910835c5c1e73da46fba01ea50d5dd76fb" ]),
	("RIPEMD160", ripemd160Hash, [
		"9c1185a5c5e9fc54612808977ee8f548b2258d31",
		"37f332f68db77bd9d7edd4969571ad671cf9dd3b",
		"132072df690933835eb8b6ad0b77e7b6f14acad7" ]),
	("Tiger", tigerHash, [
		"3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
		"6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075",
		"a8f04b0f7201a0d728101c9d26525b31764a3493fcd8458f" ])
	, ("Skein256-160", skein256Hash 160, [
		"ff800bed6d2044ee9d604a674e3fda50d9b24a72",
		"3265703c166aa3e0d7da070b9cf1b1a5953f0a77",
		"17b29aa1424b3ec022505bd215ff73fd2e6d1e5a" ])
	, ("Skein256-256", skein256Hash 256, [
		"c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba",
		"c0fbd7d779b20f0a4614a66697f9e41859eaf382f14bf857e8cdb210adb9b3fe",
		"fb2f2f2deed0e1dd7ee2b91cee34e2d1c22072e1f5eaee288c35a0723eb653cd" ])
	, ("Skein512-160", skein512Hash 160, [
		"49daf1ccebb3544bc93cb5019ba91b0eea8876ee",
		"826325ee55a6dd18c3b2dbbc9c10420f5475975e",
		"7544ec7a35712ec953f02b0d0c86641cae4eb6e5" ])
	, ("Skein512-384", skein512Hash 384, [
		"dd5aaf4589dc227bd1eb7bc68771f5baeaa3586ef6c7680167a023ec8ce26980f06c4082c488b4ac9ef313f8cbe70808",
		"f814c107f3465e7c54048a5503547deddc377264f05c706b0d19db4847b354855ee52ab6a785c238c9e710d848542041",
		"e06520eeadc1d0a44fee1d2492547499c1e58526387c8b9c53905e5edb79f9840575cbf844e21b1ad1ea126dd8a8ca6f" ])
	, ("Skein512-512", skein512Hash 512, [
		"bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a",
		"94c2ae036dba8783d0b3f7d6cc111ff810702f5c77707999be7e1c9486ff238a7044de734293147359b4ac7e1d09cd247c351d69826b78dcddd951f0ef912713",
		"7f81113575e4b4d3441940e87aca331e6d63d103fe5107f29cd877af0d0f5e0ea34164258c60da5190189d0872e63a96596d2ef25e709099842da71d64111e0f" ])
	, ("Skein512-896", skein512Hash 896, [
		"b95175236c83a459ce7ec6c12b761a838b22d750e765b3fdaa892201b2aa714bc3d1d887dd64028bbf177c1dd11baa09c6c4ddb598fd07d6a8c131a09fc5b958e2999a8006754b25abe3bf8492b7eabec70e52e04e5ac867df2393c573f16eee3244554f1d2b724f2c0437c62007f770",
		"3265708553e7d146e5c7bcbc97b3e9e9f5b53a5e4af53612bdd6454da4fa7b13d413184fe34ed57b6574be10e389d0ec4b1d2b1dd2c80e0257d5a76b2cd86a19a27b1bcb3cc24d911b5dc5ee74d19ad558fd85b5f024e99f56d1d3199f1f9f88ed85fab9f945f11cf9fc00e94e3ca4c7",
		"3d23d3db9be719bbd2119f8402a28f38d8225faa79d5b68b80738c64a82004aafc7a840cd6dd9bced6644fa894a3d8d7d2ee89525fd1956a2db052c4c2f8d2111c91ef46b0997540d42bcf384826af1a5ef6510077f52d0574cf2b46f1b6a5dad07ed40f3d21a13ca2d079fa602ff02d" ])
	]

hexalise s =
        concatMap (\c -> [ hex $ c `div` 16, hex $ c `mod` 16 ]) s
        where hex i
                | i >= 0 && i <= 9   = fromIntegral (ord '0') + i
                | i >= 10 && i <= 15 = fromIntegral (ord 'a') + i - 10
                | otherwise          = 0

hexaliseB :: B.ByteString -> B.ByteString
hexaliseB = B.pack . hexalise . B.unpack

splitB l b =
	if B.length b > l
		then
			let (b1, b2) = B.splitAt l b in
			b1 : splitB l b2
		else	
			[ b ]

showHash :: B.ByteString -> String
showHash = map (toEnum.fromEnum) . hexalise . B.unpack

runhash hash v = showHash $ (fctHash hash) $ v
runhashinc hash v = showHash $ (fctInc hash) $ v

makeTestAlg (name, hash, results) = concatMap maketest $ zip3 [0..] vectors results
	where
		testname i = name ++ " " ++ show i
		runtest v = runhash hash $ B.pack $ map (toEnum.fromEnum) v

		runtestinc i v = runhashinc hash $ splitB i $ B.pack $ map (toEnum.fromEnum) v

		maketest (i, v, r) =
			[ testname i ~: testname i ~: r ~=? (runtest v),
			  testname i ~: testname i ~: r ~=? (runtestinc 1 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 2 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 3 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 4 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 5 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 9 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 16 v) ]

mapTests :: [Test]
mapTests = concatMap makeTestAlg results

tests = TestList mapTests

main = runTestTT tests
