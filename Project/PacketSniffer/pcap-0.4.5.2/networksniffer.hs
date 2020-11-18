module Main where
import System.Console.GetOpt
import System.Environment
import System.Process
import Control.Monad
import Text.Printf
import System.Exit
import Data.Maybe
import System.IO
import Data.List
import Data.Char
import Options
import Foreign
import Network.Pcap as PCap



-- our packet output format
data PacketFmt = PacketFmt {
                   ascii       :: String,
                   hexadecimal :: [Word8]
                 }
 deriving (Eq,Show)

initPktFmt a h = 
  PacketFmt {
    ascii       = a,
    hexadecimal = h
}

hsnsVersion = "hsns: the haskell network sniffer, version 0.5.3"

formatData :: PacketFmt -> IO ()
formatData pf = do
  let (x,x') = splitAt 10 a
      (y,y') = splitAt 10 h
  unless (x' == [] && y' == []) $ do
    mapM_ (printf "%02.2x ") (fmtHex y)
    printf "\t\t%s\n" x
    formatData (initPktFmt x' y')

  -- this will be called with x' and y' are finally empty,
  -- but data still remains in our buffer

  -- note: z is the difference between how many characters
  -- we output on a 'complete' line (30) and how many
  -- we're outputting for this 'incomplete' line (every
  -- hex byte is of length 2 plus the trailing space
  when (length x < 10 && length y < 10) $ do
    mapM_ (printf "%02.2x ") (fmtHex y)
    let z = 30 - (3 * (length $ fmtHex y)) 
    fmtIrregular z
    printf "\t%s\n" x
 where
  a = ascii pf
  h = hexadecimal pf
  fmtHex :: [Word8] -> [Int]
  fmtHex bytes = [ (read $ show y) | y <- bytes] :: [Int]
  fmtIrregular :: Int -> IO ()
  fmtIrregular z = do
    printf "\t"
    if ((z-8) > 0) then fmtIrregular (z - 8) else return ()


captcha :: PCap.PktHdr -> Ptr Word8 -> IO ()
captcha pkth datap = do
  a  <- peekArray (fromIntegral (PCap.hdrCaptureLength pkth)) datap
  s  <- return $ map (\x -> if (x >= 32 && x <= 126) then x else 46) a
  s' <- return $ map (\x -> chr (read $ show x)) s
  formatData (initPktFmt s' a)
  printf "\n\n"
  hFlush stdout

starter :: HsnsOpts -> IO ()
starter o = do

  -- options that don't depend on anything else
  when ((help o) == "True") $ putStrLn (usageInfo "hsns: \"filter program\" [OPTIONS]..." options) >> exitWith ExitSuccess 
  when ((version o) == "True") $ (putStrLn hsnsVersion >> (exitWith ExitSuccess))
  when ((buffered o) == "True") $ hSetBuffering stdout LineBuffering

  -- list devices
  devs <- PCap.findAllDevs
  let devnames = map (\i -> (PCap.ifName i)) devs

  when ((iflist o) == "True") $ do
    putStrLn "interfaces:" 
    mapM_ (printf " -- %s\n") devnames
    exitWith ExitSuccess

  -- variables that depend on root access
  let dev      = (interface o)
  net  <- PCap.lookupNet dev
  spy  <- PCap.openLive dev (read $ snarflen o) (if (nopromiscuous o) == "True" then True else False) 100000
  -- set filter
  unless (null (bpf o)) $ do PCap.setFilter spy (bpf o) False (PCap.netMask net)

  -- loop and capture
  PCap.loop spy (read $ count o) captcha
  --print statistics
  s <- PCap.statistics spy
  putStrLn ("Packets recieved: " ++ (show $ PCap.statReceived s))
  putStrLn ("Packets dropped: " ++ (show $ PCap.statDropped s))
  putStrLn ("Packets dropped by interface: " ++ (show $ PCap.statIfaceDropped s))


main = do
  (o,n)  <- parseOpts -- our options and filter in a pair, we assume the filter is the first thing
                      -- on the command line

  starter (create o n)
  return ()
 where
  parseOpts     = (getArgs >>= hsnsOptions)
  create x f =
    let y = construct x in
    Opts {count         = fromMaybe "5"        (lookup "count"     y),
          snarflen      = fromMaybe "68"       (lookup "snarf"     y),
          interface     = fromMaybe "eth0"     (lookup "listen"    y),
          version       = fromMaybe "False"    (lookup "version"   y),
          nopromiscuous = fromMaybe "False"    (lookup "nopromisc" y),
          iflist        = fromMaybe "False"    (lookup "ifList"    y),
          buffered      = fromMaybe "False"    (lookup "buffered"  y),
          help          = fromMaybe "False"    (lookup "help"      y),
          bpf           = if f == [] then "" else (f !! 0)
         }

  construct   f = map construct' f
   where
     construct' x = case x of
       Help          -> ("help","True")
       Count    s    -> ("count",s)
       SnarfLen s    -> ("snarf",s)
       Listen   s    -> ("listen",s)
       NoPromiscuous -> ("nopromisc","True")
       IfList        -> ("ifList","True")
       LineBuffered  -> ("buffered","True")
       Version       -> ("version","True")