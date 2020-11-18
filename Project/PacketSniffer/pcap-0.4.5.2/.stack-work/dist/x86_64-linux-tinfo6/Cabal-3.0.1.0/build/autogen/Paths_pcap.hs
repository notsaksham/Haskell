{-# LANGUAGE CPP #-}
{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
module Paths_pcap (
    version,
    getBinDir, getLibDir, getDynLibDir, getDataDir, getLibexecDir,
    getDataFileName, getSysconfDir
  ) where

import qualified Control.Exception as Exception
import Data.Version (Version(..))
import System.Environment (getEnv)
import Prelude

#if defined(VERSION_base)

#if MIN_VERSION_base(4,0,0)
catchIO :: IO a -> (Exception.IOException -> IO a) -> IO a
#else
catchIO :: IO a -> (Exception.Exception -> IO a) -> IO a
#endif

#else
catchIO :: IO a -> (Exception.IOException -> IO a) -> IO a
#endif
catchIO = Exception.catch

version :: Version
version = Version [0,4,5,2] []
bindir, libdir, dynlibdir, datadir, libexecdir, sysconfdir :: FilePath

bindir     = "/run/media/saksham/Documents/Haskell/Project/PacketSniffer/pcap-0.4.5.2/.stack-work/install/x86_64-linux-tinfo6/6c803ed9cbfb426f3944f37ee56d6d435aacf686604d476b9e8d0595d4bdfbb2/8.8.4/bin"
libdir     = "/run/media/saksham/Documents/Haskell/Project/PacketSniffer/pcap-0.4.5.2/.stack-work/install/x86_64-linux-tinfo6/6c803ed9cbfb426f3944f37ee56d6d435aacf686604d476b9e8d0595d4bdfbb2/8.8.4/lib/x86_64-linux-ghc-8.8.4/pcap-0.4.5.2-7F2QihPEJKV9379Mm2lVwv"
dynlibdir  = "/run/media/saksham/Documents/Haskell/Project/PacketSniffer/pcap-0.4.5.2/.stack-work/install/x86_64-linux-tinfo6/6c803ed9cbfb426f3944f37ee56d6d435aacf686604d476b9e8d0595d4bdfbb2/8.8.4/lib/x86_64-linux-ghc-8.8.4"
datadir    = "/run/media/saksham/Documents/Haskell/Project/PacketSniffer/pcap-0.4.5.2/.stack-work/install/x86_64-linux-tinfo6/6c803ed9cbfb426f3944f37ee56d6d435aacf686604d476b9e8d0595d4bdfbb2/8.8.4/share/x86_64-linux-ghc-8.8.4/pcap-0.4.5.2"
libexecdir = "/run/media/saksham/Documents/Haskell/Project/PacketSniffer/pcap-0.4.5.2/.stack-work/install/x86_64-linux-tinfo6/6c803ed9cbfb426f3944f37ee56d6d435aacf686604d476b9e8d0595d4bdfbb2/8.8.4/libexec/x86_64-linux-ghc-8.8.4/pcap-0.4.5.2"
sysconfdir = "/run/media/saksham/Documents/Haskell/Project/PacketSniffer/pcap-0.4.5.2/.stack-work/install/x86_64-linux-tinfo6/6c803ed9cbfb426f3944f37ee56d6d435aacf686604d476b9e8d0595d4bdfbb2/8.8.4/etc"

getBinDir, getLibDir, getDynLibDir, getDataDir, getLibexecDir, getSysconfDir :: IO FilePath
getBinDir = catchIO (getEnv "pcap_bindir") (\_ -> return bindir)
getLibDir = catchIO (getEnv "pcap_libdir") (\_ -> return libdir)
getDynLibDir = catchIO (getEnv "pcap_dynlibdir") (\_ -> return dynlibdir)
getDataDir = catchIO (getEnv "pcap_datadir") (\_ -> return datadir)
getLibexecDir = catchIO (getEnv "pcap_libexecdir") (\_ -> return libexecdir)
getSysconfDir = catchIO (getEnv "pcap_sysconfdir") (\_ -> return sysconfdir)

getDataFileName :: FilePath -> IO FilePath
getDataFileName name = do
  dir <- getDataDir
  return (dir ++ "/" ++ name)
