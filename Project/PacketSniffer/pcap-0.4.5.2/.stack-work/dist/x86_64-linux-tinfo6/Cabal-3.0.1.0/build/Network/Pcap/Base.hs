{-# LINE 1 "Network/Pcap/Base.hsc" #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
------------------------------------------------------------------------------
-- |
--  Module      : Network.Pcap.Base
--  Copyright   : Bryan O'Sullivan 2007, Antiope Associates LLC 2004
--  License     : BSD-style
--  Maintainer  : bos@serpentine.com
--  Stability   : experimental
--  Portability : non-portable
--
-- The 'Network.Pcap.Base' module is a low-level binding to all of the
-- functions in @libpcap@.  See <http://www.tcpdump.org> for more
-- information.
--
-- Only a minimum of marshaling is done.  For a higher-level interface
-- that\'s more friendly, use the 'Network.Pcap' module.
--
-- To convert captured packet data to a list, extract the length of
-- the captured buffer from the packet header record and use
-- 'peekArray' to convert the captured data to a list.  For
-- illustration:
--
-- > import Foreign
-- > import Network.Pcap.Base
-- >
-- > main :: IO ()
-- > main = do
-- >     p <- openLive "eth0" 100 True 10000
-- >     withForeignPtr p $ \ptr ->
-- >       dispatch ptr (-1) printIt
-- >     return ()
-- >
-- > printIt :: PktHdr -> Ptr Word8 -> IO ()
-- > printIt ph bytep =
-- >     peekArray (fromIntegral (hdrCaptureLength ph)) bytep >>= print
--
-- Note that the 'SockAddr' exported here is not the @SockAddr@ from
-- 'Network.Socket'. The @SockAddr@ from 'Network.Socket' corresponds
-- to @struct sockaddr_in@ in BSD terminology. The 'SockAddr' record
-- here is BSD's @struct sockaddr@. See W.R.Stevens, TCP Illustrated,
-- volume 2, for further elucidation.
--
-- This binding should be portable across systems that can use the
-- @libpcap@ library from @tcpdump.org@. It will not work with
-- Winpcap, a similar library for Windows, although adapting it should
-- not prove difficult.
--
------------------------------------------------------------------------------

module Network.Pcap.Base
    (
      -- * Types
      PcapTag
    , PcapDumpTag
    , Pdump
    , BpfProgram
    , BpfProgramTag
    , Callback
    , Direction(..)
    , Link(..)
    , Interface(..)
    , PcapAddr(..)
    , SockAddr(..)
    , Network(..)
    , PktHdr(..)
    , Statistics(..)

    -- * Device opening
    , openOffline               -- :: FilePath -> IO Pcap
    , openLive                  -- :: String -> Int -> Bool -> Int -> IO Pcap
    , openDead                  -- :: Int    -> Int -> IO Pcap
    , openDump                  -- :: Ptr PcapTag -> FilePath -> IO Pdump

    -- * Filter handling
    , setFilter                 -- :: Ptr PcapTag -> String -> Bool -> Word32 -> IO ()
    , compileFilter             -- :: Int -> Int -> String -> Bool -> Word32 -> IO BpfProgram

    -- * Device utilities
    , lookupDev                 -- :: IO String
    , findAllDevs               -- :: IO [Interface]
    , lookupNet                 -- :: String -> IO Network

    -- * Interface control

    , setNonBlock               -- :: Ptr PcapTag -> Bool -> IO ()
    , getNonBlock               -- :: Ptr PcapTag -> IO Bool
    , setDirection

    -- * Link layer utilities
    , datalink                  -- :: Ptr PcapTag -> IO Link
    , setDatalink               -- :: Ptr PcapTag -> Link -> IO ()
    , listDatalinks             -- :: Ptr PcapTag -> IO [Link]

    -- * Packet processing
    , dispatch                  -- :: Ptr PcapTag -> Int -> Callback -> IO Int
    , loop                      -- :: Ptr PcapTag -> Int -> Callback -> IO Int
    , next                      -- :: Ptr PcapTag -> IO (PktHdr, Ptr Word8)
    , dump                      -- :: Ptr PcapDumpTag -> Ptr PktHdr -> Ptr Word8 -> IO ()

    -- * Sending packets
    , sendPacket

    -- * Conversion
    , toPktHdr

    -- * Miscellaneous
    , statistics                -- :: Ptr PcapTag -> IO Statistics
    , version                   -- :: Ptr PcapTag -> IO (Int, Int)
    , isSwapped                 -- :: Ptr PcapTag -> IO Bool
    , snapshotLen               -- :: Ptr PcapTag -> IO Int
    ) where

import Control.Monad (when)
import Data.Maybe (isNothing, fromJust )
import Data.ByteString ()

{-# LINE 119 "Network/Pcap/Base.hsc" #-}
import qualified Data.ByteString.Internal as B

{-# LINE 121 "Network/Pcap/Base.hsc" #-}
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr, plusPtr, nullPtr, FunPtr, freeHaskellFunPtr)
import Foreign.C.String (CString, peekCString, withCString)
import Foreign.C.Types (CInt(..), CUInt, CChar, CUChar, CLong)
import Foreign.Concurrent (newForeignPtr)
import Foreign.ForeignPtr (ForeignPtr)
import Foreign.Marshal.Alloc (alloca, allocaBytes, free)
import Foreign.Marshal.Array (allocaArray, peekArray)
import Foreign.Marshal.Utils (fromBool, toBool)
import Foreign.Storable (Storable(..))
import Network.Socket (Family(..), unpackFamily)





newtype BpfProgramTag = BpfProgramTag ()

-- | Compiled Berkeley Packet Filter program.
type BpfProgram = ForeignPtr BpfProgramTag

newtype PcapTag = PcapTag ()

-- | Packet capture descriptor.
newtype PcapDumpTag = PcapDumpTag ()

-- | Dump file descriptor.
type Pdump = ForeignPtr PcapDumpTag

data PktHdr = PktHdr {
      hdrSeconds :: {-# UNPACK #-} !Word32       -- ^ timestamp (seconds)
    , hdrUseconds :: {-# UNPACK #-} !Word32      -- ^ timestamp (microseconds)
    , hdrCaptureLength :: {-# UNPACK #-} !Word32 -- ^ number of bytes present in capture
    , hdrWireLength :: {-# UNPACK #-} !Word32    -- ^ number of bytes on the wire
    } deriving (Eq, Show)

data Statistics = Statistics {
      statReceived :: {-# UNPACK #-} !Word32     -- ^ packets received
    , statDropped :: {-# UNPACK #-} !Word32      -- ^ packets dropped by @libpcap@
    , statIfaceDropped :: {-# UNPACK #-} !Word32 -- ^ packets dropped by the network interface
    } deriving (Eq, Show)

type ErrBuf = Ptr CChar

--
-- Data types for interface list
--

-- | The interface structure.
data Interface = Interface {
      ifName :: String          -- ^ the interface name
    , ifDescription :: String   -- ^ interface description string (if any)
    , ifAddresses :: [PcapAddr] -- ^ address families supported by this interface
    , ifFlags :: Word32
    } deriving (Eq, Read, Show)

-- | The address structure.
data PcapAddr = PcapAddr {
      addrSA  :: SockAddr         -- ^ interface address
    , addrMask  :: Maybe SockAddr -- ^ network mask
    , addrBcast :: Maybe SockAddr -- ^ broadcast address
    , addrPeer  :: Maybe SockAddr -- ^ address of peer, of a point-to-point link
    } deriving (Eq, Read, Show)

-- | The socket address record. Note that this is not the same as
-- SockAddr from 'Network.Socket'. (That is a Haskell version of C\'s
-- @struct sockaddr_in@. This is the real @struct sockaddr@ from the
-- BSD network stack.)
data SockAddr = SockAddr {
      saFamily  :: !Family       -- ^ an address family exported by Network.Socket
    , saAddr    :: {-# UNPACK #-} !B.ByteString
    } deriving (Eq, Read, Show)

-- | The network address record. Both the address and mask are in
-- network byte order.
data Network = Network {
      netAddr :: {-# UNPACK #-} !Word32 -- ^ IPv4 network address
    , netMask :: {-# UNPACK #-} !Word32 -- ^ IPv4 netmask
    } deriving (Eq, Read, Show)

withErrBuf :: (a -> Bool) -> (ErrBuf -> IO a) -> IO a
withErrBuf isError f = allocaArray (256) $ \errPtr -> do
{-# LINE 203 "Network/Pcap/Base.hsc" #-}
    ret <- f errPtr
    if isError ret
      then peekCString errPtr >>= ioError . userError
      else return ret

withErrBuf_ :: (a -> Bool) -> (ErrBuf -> IO a) -> IO ()
withErrBuf_ isError f = withErrBuf isError f >> return ()

-- | 'openOffline' opens a dump file for reading. The file format is
-- the same as used by @tcpdump@ and Wireshark. The string @\"-\"@ is
-- a synonym for @stdin@.
openOffline :: FilePath -- ^ filename
            -> IO (ForeignPtr PcapTag)
openOffline name =
    withCString name $ \namePtr -> do
      ptr <- withErrBuf (== nullPtr) (pcap_open_offline namePtr)
      newForeignPtr ptr (pcap_close ptr)

-- | 'openLive' is used to get a packet descriptor that can be used to
-- look at packets on the network. The arguments are the device name,
-- the snapshot length (in bytes), the promiscuity of the interface
-- ('True' == promiscuous) and a timeout in milliseconds.
--
-- Using @\"any\"@ as the device name will capture packets from all
-- interfaces.  On some systems, reading from the @\"any\"@ device is
-- incompatible with setting the interfaces into promiscuous mode. In
-- that case, only packets whose link layer addresses match those of
-- the interfaces are captured.
--
openLive :: String -- ^ device name
         -> Int    -- ^ snapshot length
         -> Bool   -- ^ set to promiscuous mode?
         -> Int    -- ^ timeout in milliseconds
         -> IO (ForeignPtr PcapTag)
openLive name snaplen promisc timeout =
    withCString name $ \namePtr -> do
      ptr <- withErrBuf (== nullPtr) $ pcap_open_live namePtr
             (fromIntegral snaplen) (fromBool promisc) (fromIntegral timeout)
      newForeignPtr ptr (pcap_close ptr)

-- | 'openDead' is used to get a packet capture descriptor without
-- opening a file or device. It is typically used to test packet
-- filter compilation by 'setFilter'. The arguments are the link type
-- and the snapshot length.
--
openDead :: Link                    -- ^ datalink type
         -> Int                     -- ^ snapshot length
         -> IO (ForeignPtr PcapTag) -- ^ packet capture descriptor
openDead link snaplen = do
    ptr <- pcap_open_dead (packLink link)
           (fromIntegral snaplen)
    when (ptr == nullPtr) $
        ioError $ userError "Can't open dead pcap device"
    newForeignPtr ptr (pcap_close ptr)

foreign import ccall unsafe pcap_open_offline
    :: CString   -> ErrBuf -> IO (Ptr PcapTag)
foreign import ccall unsafe pcap_close
    :: Ptr PcapTag -> IO ()
foreign import ccall unsafe pcap_open_live
    :: CString -> CInt -> CInt -> CInt -> ErrBuf -> IO (Ptr PcapTag)
foreign import ccall unsafe pcap_open_dead
    :: CInt -> CInt -> IO (Ptr PcapTag)

--
-- Open a dump device
--

-- | 'openDump' opens a dump file for writing. This dump file is
-- written to by the 'dump' function. The arguments are a raw packet
-- capture descriptor and the file name, with \"-\" as a synonym for
-- @stdout@.
openDump :: Ptr PcapTag -- ^ packet capture descriptor
         -> FilePath    -- ^ dump file name
         -> IO Pdump    -- ^ savefile descriptor
openDump hdl name =
    withCString name $ \namePtr -> do
      ptr <- pcap_dump_open hdl namePtr >>= throwPcapIf hdl (== nullPtr)
      newForeignPtr ptr (pcap_dump_close ptr)

foreign import ccall unsafe pcap_dump_open
    :: Ptr PcapTag -> CString -> IO (Ptr PcapDumpTag)
foreign import ccall unsafe pcap_dump_close
    :: Ptr PcapDumpTag -> IO ()

--
-- Set the filter
--

-- | Set a filter on the specified packet capture descriptor. Valid
-- filter strings are those accepted by @tcpdump@.
setFilter :: Ptr PcapTag -- ^ packet capture descriptor
          -> String      -- ^ filter string
          -> Bool        -- ^ optimize?
          -> Word32      -- ^ IPv4 network mask
          -> IO ()
setFilter hdl filt opt mask =
    withCString filt $ \filtstr -> do
      allocaBytes ((16)) $ \bpfp -> do
{-# LINE 302 "Network/Pcap/Base.hsc" #-}
        pcap_compile hdl bpfp filtstr (fromBool opt) (fromIntegral mask) >>=
            throwPcapIf_ hdl (== -1)
        pcap_setfilter hdl bpfp >>= throwPcapIf_ hdl (== -1)
        pcap_freecode bpfp

-- | Compile a filter for use by another program using the Berkeley
-- Packet Filter library.
compileFilter :: Int    -- ^ snapshot length
              -> Link   -- ^ datalink type
              -> String -- ^ filter string
              -> Bool   -- ^ optimize?
              -> Word32 -- ^ IPv4 network mask
              -> IO BpfProgram
compileFilter snaplen link filt opt mask =
    withCString filt $ \filtstr ->
      allocaBytes ((16)) $ \bpfp -> do
{-# LINE 318 "Network/Pcap/Base.hsc" #-}
        ret  <- pcap_compile_nopcap (fromIntegral snaplen)
                  (packLink link)
                  bpfp
                  filtstr
                  (fromBool opt)
                  (fromIntegral mask)
        when (ret == (-1)) $
            ioError $ userError "Pcap.compileFilter error"
        newForeignPtr bpfp (pcap_freecode bpfp)

foreign import ccall pcap_compile
        :: Ptr PcapTag  -> Ptr BpfProgramTag -> CString -> CInt -> CInt
        -> IO CInt
foreign import ccall pcap_compile_nopcap
        :: CInt -> CInt -> Ptr BpfProgramTag -> CString -> CInt -> CInt
        -> IO CInt
foreign import ccall pcap_setfilter
        :: Ptr PcapTag  -> Ptr BpfProgramTag -> IO CInt
foreign import ccall pcap_freecode
        :: Ptr BpfProgramTag -> IO ()

--
-- Find devices
--

newtype DevBuf = DevBuf ()
newtype DevAddr = DevAddr ()

-- | 'lookupDev' returns the name of a device suitable for use with
-- 'openLive' and 'lookupNet'. If you only have one interface, it is
-- the function of choice. If not, see 'findAllDevs'.
lookupDev :: IO String
lookupDev = withErrBuf (== nullPtr) pcap_lookupdev >>= peekCString

-- | 'findAllDevs' returns a list of all the network devices that can
-- be opened by 'openLive'. It returns only those devices that the
-- calling process has sufficient privileges to open, so it may not
-- find every device on the system.
findAllDevs :: IO [Interface]
findAllDevs =
    alloca $ \dptr -> do
      withErrBuf_ (== -1) (pcap_findalldevs dptr)
      dbuf <- peek dptr
      dl <- devs2list dbuf
      pcap_freealldevs dbuf
      return dl

devs2list :: Ptr DevBuf -> IO [Interface]
devs2list dbuf
    | dbuf == nullPtr = return []
    | otherwise = do
        nextdev <- ((\hsc_ptr -> peekByteOff hsc_ptr 0)) dbuf
{-# LINE 370 "Network/Pcap/Base.hsc" #-}
        ds <- devs2list nextdev
        d <- oneDev dbuf
        return (d : ds)

oneDev :: Ptr DevBuf -> IO Interface
oneDev dbuf = do
    name  <- ((\hsc_ptr -> peekByteOff hsc_ptr 8)) dbuf
{-# LINE 377 "Network/Pcap/Base.hsc" #-}
    desc  <- ((\hsc_ptr -> peekByteOff hsc_ptr 16)) dbuf
{-# LINE 378 "Network/Pcap/Base.hsc" #-}
    addrs <- ((\hsc_ptr -> peekByteOff hsc_ptr 24)) dbuf
{-# LINE 379 "Network/Pcap/Base.hsc" #-}
    flags <- ((\hsc_ptr -> peekByteOff hsc_ptr 32)) dbuf
{-# LINE 380 "Network/Pcap/Base.hsc" #-}

    name' <- peekCString name
    desc' <- if desc /= nullPtr
             then peekCString desc
             else return ""

    addrs' <- addrs2list addrs

    return Interface { ifName = name'
                     , ifDescription = desc'
                     , ifAddresses = addrs'
                     , ifFlags = fromIntegral (flags :: CUInt)
                     }

addrs2list :: Ptr DevAddr -> IO [PcapAddr]
addrs2list abuf
    | abuf == nullPtr = return []
    | otherwise = do
        nextaddr <- ((\hsc_ptr -> peekByteOff hsc_ptr 0)) abuf
{-# LINE 399 "Network/Pcap/Base.hsc" #-}
        as <- addrs2list nextaddr
        a <- oneAddr abuf
        return (a : as)

oneAddr :: Ptr DevAddr -> IO PcapAddr
oneAddr abuf =
    let socka :: Ptr a -> IO (Maybe SockAddr)
        socka sa | sa == nullPtr = return Nothing
                 | otherwise = do

{-# LINE 411 "Network/Pcap/Base.hsc" #-}
          l <- return ((16)) :: IO CUChar
{-# LINE 412 "Network/Pcap/Base.hsc" #-}

{-# LINE 413 "Network/Pcap/Base.hsc" #-}
          f <- (((\hsc_ptr -> peekByteOff hsc_ptr 0)) sa) :: IO CUChar
{-# LINE 414 "Network/Pcap/Base.hsc" #-}

          let off = ((2))
{-# LINE 416 "Network/Pcap/Base.hsc" #-}
              nbytes = ((fromIntegral l) - off)
          addr <- B.create nbytes $ \p ->
                  B.memcpy p (plusPtr sa off :: Ptr Word8)
                       (fromIntegral nbytes)

          return (Just (SockAddr (unpackFamily (fromIntegral f)) addr))
    in do
      addr <- socka =<< ((\hsc_ptr -> peekByteOff hsc_ptr 8)) abuf
{-# LINE 424 "Network/Pcap/Base.hsc" #-}

      when (isNothing addr) $
           ioError $ userError "Pcap.oneAddr: null address"

      mask <- socka =<< ((\hsc_ptr -> peekByteOff hsc_ptr 16)) abuf
{-# LINE 429 "Network/Pcap/Base.hsc" #-}
      bcast <- socka =<< ((\hsc_ptr -> peekByteOff hsc_ptr 24)) abuf
{-# LINE 430 "Network/Pcap/Base.hsc" #-}
      peer <- socka =<< ((\hsc_ptr -> peekByteOff hsc_ptr 32)) abuf
{-# LINE 431 "Network/Pcap/Base.hsc" #-}

      return PcapAddr { addrSA = fromJust addr
                      , addrMask = mask
                      , addrBcast = bcast
                      , addrPeer = peer
                      }

-- | Return the network address and mask for the specified interface
-- name. Only valid for IPv4. For other protocols, use 'findAllDevs'
-- and search the 'Interface' list for the associated network mask.
lookupNet :: String     -- ^ device name
          -> IO Network
lookupNet dev = withCString dev $ \name  ->
    alloca $ \netp -> alloca $ \maskp -> do
      withErrBuf_ (== -1) (pcap_lookupnet name netp maskp)
      net  <- peek netp
      mask <- peek maskp

      return Network { netAddr = fromIntegral net
                     , netMask = fromIntegral mask
                     }

foreign import ccall unsafe pcap_lookupdev
    :: CString -> IO CString
foreign import ccall unsafe pcap_findalldevs
    :: Ptr (Ptr DevBuf) -> ErrBuf -> IO CInt
foreign import ccall unsafe pcap_freealldevs
    :: Ptr DevBuf -> IO ()
foreign import ccall unsafe pcap_lookupnet
    :: CString -> Ptr CUInt -> Ptr CUInt -> ErrBuf -> IO CInt

--
-- Set or read the device mode (blocking/nonblocking)
--

-- | Set a packet capture descriptor into non-blocking mode if the
-- second argument is 'True', otherwise put it in blocking mode. Note
-- that the packet capture descriptor must have been obtained from
-- 'openLive'.
--
setNonBlock :: Ptr PcapTag -> Bool -> IO ()
setNonBlock hdl block =
    withErrBuf_ (== -1) (pcap_setnonblock hdl (fromBool block))

-- | Return the blocking status of the packet capture
-- descriptor. 'True' indicates that the descriptor is
-- non-blocking. Descriptors referring to dump files opened by
-- 'openDump' always return 'False'.
getNonBlock :: Ptr PcapTag -> IO Bool
getNonBlock hdl = toBool `fmap` withErrBuf (== -1) (pcap_getnonblock hdl)

-- | The direction in which packets are to be captured.  See
-- 'setDirection'.
data Direction = InOut -- ^ incoming and outgoing packets (the default)
               | In    -- ^ incoming packets
               | Out   -- ^ outgoing packets
                 deriving (Eq, Show, Read)

-- | Specify the direction in which packets are to be captured.
-- Complete functionality is not necessarily available on all
-- platforms.
setDirection :: Ptr PcapTag -> Direction -> IO ()
setDirection hdl dir =
    pcap_setdirection hdl (packDirection dir) >>= throwPcapIf_ hdl (== -1)

packDirection :: Direction -> CInt
packDirection In = (1)
{-# LINE 498 "Network/Pcap/Base.hsc" #-}
packDirection Out = (2)
{-# LINE 499 "Network/Pcap/Base.hsc" #-}
packDirection InOut = (0)
{-# LINE 500 "Network/Pcap/Base.hsc" #-}

foreign import ccall unsafe pcap_setnonblock
    :: Ptr PcapTag -> CInt -> ErrBuf -> IO CInt
foreign import ccall unsafe pcap_getnonblock
    :: Ptr PcapTag -> ErrBuf -> IO CInt
foreign import ccall unsafe pcap_setdirection
    :: Ptr PcapTag -> CInt -> IO CInt

--
-- Error handling
--

throwPcapIf :: Ptr PcapTag -> (a -> Bool) -> a -> IO a
throwPcapIf hdl p v = if p v
    then pcap_geterr hdl >>= peekCString >>= ioError . userError
    else return v

throwPcapIf_ :: Ptr PcapTag -> (a -> Bool) -> a -> IO ()
throwPcapIf_ hdl p v = throwPcapIf hdl p v >> return ()

foreign import ccall unsafe pcap_geterr
    :: Ptr PcapTag -> IO CString

-- | Send a raw packet through the network interface.
sendPacket :: Ptr PcapTag
           -> Ptr Word8 -- ^ packet data (including link-level header)
           -> Int       -- ^ packet size
           -> IO ()
sendPacket hdl buf size =
    pcap_sendpacket hdl buf (fromIntegral size) >>= throwPcapIf_ hdl (== -1)

foreign import ccall unsafe pcap_sendpacket
    :: Ptr PcapTag -> Ptr Word8 -> CInt -> IO CInt

-- | the type of the callback function passed to 'dispatch' or 'loop'.
type Callback  = PktHdr    -> Ptr Word8  -> IO ()
type CCallback = Ptr Word8 -> Ptr PktHdr -> Ptr Word8 -> IO ()

toPktHdr :: Ptr PktHdr -> IO PktHdr
toPktHdr hdr = do
    let ts = ((\hsc_ptr -> hsc_ptr `plusPtr` 0)) hdr
{-# LINE 541 "Network/Pcap/Base.hsc" #-}

    s <- ((\hsc_ptr -> peekByteOff hsc_ptr 0)) ts
{-# LINE 543 "Network/Pcap/Base.hsc" #-}
    us <- ((\hsc_ptr -> peekByteOff hsc_ptr 8)) ts
{-# LINE 544 "Network/Pcap/Base.hsc" #-}
    caplen <- ((\hsc_ptr -> peekByteOff hsc_ptr 16)) hdr
{-# LINE 545 "Network/Pcap/Base.hsc" #-}
    len <- ((\hsc_ptr -> peekByteOff hsc_ptr 20)) hdr
{-# LINE 546 "Network/Pcap/Base.hsc" #-}

    return PktHdr { hdrSeconds = fromIntegral (s :: CLong)
                  , hdrUseconds = fromIntegral (us :: CLong)
                  , hdrCaptureLength = fromIntegral (caplen :: CUInt)
                  , hdrWireLength = fromIntegral (len :: CUInt)
                  }

exportCallback :: Callback -> IO (FunPtr CCallback)
exportCallback f = exportCCallback $ \_user chdr ptr -> do
    hdr <- toPktHdr chdr
    f hdr ptr

-- | Collect and process packets. The arguments are the packet capture
-- descriptor, the count and a callback function.
--
-- The count is the maximum number of packets to process before
-- returning.  A count of -1 means process all of the packets received
-- in one buffer (if a live capture) or all of the packets in a dump
-- file (if offline).
--
-- The callback function is passed two arguments, a packet header
-- record and a pointer to the packet data (@Ptr Word8@). The header
-- record contains the number of bytes captured, which can be used to
-- marshal the data into a list or array.
--
dispatch :: Ptr PcapTag -- ^ packet capture descriptor
         -> Int         -- ^ number of packets to process
         -> Callback    -- ^ packet processing function
         -> IO Int      -- ^ number of packets read
dispatch hdl count f = do
    handler <- exportCallback f
    result  <- pcap_dispatch hdl (fromIntegral count) handler nullPtr

    freeHaskellFunPtr handler

    fromIntegral `fmap` throwPcapIf hdl (== -1) result

-- | Similar to 'dispatch', but loop until the number of packets
-- specified by the second argument are read. A negative value loops
-- forever.
--
-- This function does not return when a live read timeout occurs. Use
-- 'dispatch' instead if you want to specify a timeout.
loop :: Ptr PcapTag -- ^ packet capture descriptor
     -> Int         -- ^ number of packet to read
     -> Callback    -- ^ packet processing function
     -> IO Int      -- ^ number of packets read
loop hdl count f = do
    handler <- exportCallback f
    result  <- pcap_loop hdl (fromIntegral count) handler nullPtr

    freeHaskellFunPtr handler

    fromIntegral `fmap` throwPcapIf hdl (== -1) result

-- | Read the next packet (equivalent to calling 'dispatch' with a
-- count of 1).
next :: Ptr PcapTag            -- ^ packet capture descriptor
     -> IO (PktHdr, Ptr Word8) -- ^ packet header and data of the next packet
next hdl =
    allocaBytes ((24)) $ \chdr -> do
{-# LINE 607 "Network/Pcap/Base.hsc" #-}
      ptr <- pcap_next hdl chdr
      if (ptr == nullPtr)
        then return (PktHdr 0 0 0 0, ptr)
        else do
          hdr <- toPktHdr chdr
          return (hdr, ptr)

-- | Write the packet data given by the second and third arguments to
-- a dump file opened by 'openDead'. 'dump' is designed so it can be
-- easily used as a default callback function by 'dispatch' or 'loop'.
dump :: Ptr PcapDumpTag -- ^ dump file descriptor
     -> Ptr PktHdr      -- ^ packet header record
     -> Ptr Word8       -- ^ packet data
     -> IO ()
dump hdl hdr pkt = pcap_dump hdl hdr pkt

foreign import ccall "wrapper" exportCCallback
        :: CCallback -> IO (FunPtr CCallback)

foreign import ccall pcap_dispatch
        :: Ptr PcapTag -> CInt -> FunPtr CCallback -> Ptr Word8 -> IO CInt
foreign import ccall pcap_loop
        :: Ptr PcapTag -> CInt -> FunPtr CCallback -> Ptr Word8 -> IO CInt
foreign import ccall pcap_next
        :: Ptr PcapTag -> Ptr PktHdr -> IO (Ptr Word8)
foreign import ccall pcap_dump
        :: Ptr PcapDumpTag -> Ptr PktHdr -> Ptr Word8 -> IO ()

--
-- Datalink manipulation
--

-- | Returns the datalink type associated with the given pcap
-- descriptor.
--
datalink :: Ptr PcapTag -> IO Link
datalink hdl = unpackLink `fmap` pcap_datalink hdl

-- | Sets the datalink type for a given pcap descriptor.
--
setDatalink :: Ptr PcapTag -> Link -> IO ()
setDatalink hdl link =
    pcap_set_datalink hdl (packLink link) >>= throwPcapIf_ hdl (== -1)

-- | List all the datalink types supported by a pcap descriptor.
-- Entries from the resulting list are valid arguments to
-- 'setDatalink'.
listDatalinks :: Ptr PcapTag -> IO [Link]
listDatalinks hdl =
    alloca $ \lptr -> do
      ret <- pcap_list_datalinks hdl lptr >>= throwPcapIf hdl (== -1)
      dlbuf <- peek lptr
      dls <- peekArray (fromIntegral (ret :: CInt)) dlbuf
      free dlbuf
      return (map unpackLink dls)

foreign import ccall unsafe pcap_datalink
    :: Ptr PcapTag -> IO CInt
foreign import ccall unsafe pcap_set_datalink
    :: Ptr PcapTag -> CInt -> IO CInt
foreign import ccall unsafe pcap_list_datalinks
    :: Ptr PcapTag -> Ptr (Ptr CInt) -> IO CInt

--
-- Statistics
--

-- | Returns the number of packets received, the number of packets
-- dropped by the packet filter and the number of packets dropped by
-- the interface (before processing by the packet filter).
--
statistics :: Ptr PcapTag -> IO Statistics
statistics hdl =
    allocaBytes ((12)) $ \stats -> do
{-# LINE 681 "Network/Pcap/Base.hsc" #-}
      pcap_stats hdl stats >>= throwPcapIf_ hdl (== -1)
      recv   <- ((\hsc_ptr -> peekByteOff hsc_ptr 0)) stats
{-# LINE 683 "Network/Pcap/Base.hsc" #-}
      pdrop  <- ((\hsc_ptr -> peekByteOff hsc_ptr 4)) stats
{-# LINE 684 "Network/Pcap/Base.hsc" #-}
      ifdrop <- ((\hsc_ptr -> peekByteOff hsc_ptr 8)) stats
{-# LINE 685 "Network/Pcap/Base.hsc" #-}

      return Statistics { statReceived = fromIntegral (recv :: CUInt)
                        , statDropped = fromIntegral (pdrop :: CUInt)
                        , statIfaceDropped = fromIntegral (ifdrop :: CUInt)
                        }

foreign import ccall unsafe pcap_stats
    :: Ptr PcapTag -> Ptr Statistics -> IO Int

-- | Version of the library.  The returned pair consists of the major
-- and minor version numbers.
version :: Ptr PcapTag -> IO (Int, Int)
version hdl = do
  major <- pcap_major_version hdl
  minor <- pcap_minor_version hdl
  return (fromIntegral major, fromIntegral minor)

-- | 'isSwapped' returns 'True' if the current dump file uses a
-- different byte order than the one native to the system.
isSwapped :: Ptr PcapTag -> IO Bool
isSwapped hdl = toBool `fmap` pcap_is_swapped hdl

-- | The snapshot length that was used in the call to 'openLive'.
snapshotLen :: Ptr PcapTag -> IO Int
snapshotLen hdl = fromIntegral `fmap` pcap_snapshot hdl

foreign import ccall pcap_major_version
    :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_minor_version
    :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_is_swapped
    :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_snapshot
    :: Ptr PcapTag -> IO CInt

--
-- Utility functions for data link types
--

-- | Datalink types.
--
--   This covers all of the datalink types defined in bpf.h.  Types
--   defined on your system may vary.
--
data Link
    = DLT_NULL                          -- ^ no link layer encapsulation
    | DLT_UNKNOWN Int                   -- ^ unknown encapsulation

{-# LINE 733 "Network/Pcap/Base.hsc" #-}
    | DLT_EN10MB                        -- ^ 10 Mbit per second (or faster) ethernet

{-# LINE 735 "Network/Pcap/Base.hsc" #-}

{-# LINE 736 "Network/Pcap/Base.hsc" #-}
    | DLT_EN3MB                         -- ^ original 3 Mbit per second ethernet

{-# LINE 738 "Network/Pcap/Base.hsc" #-}

{-# LINE 739 "Network/Pcap/Base.hsc" #-}
    | DLT_AX25                          -- ^ amateur radio AX.25

{-# LINE 741 "Network/Pcap/Base.hsc" #-}

{-# LINE 742 "Network/Pcap/Base.hsc" #-}
    | DLT_PRONET                        -- ^ Proteon ProNET Token Ring

{-# LINE 744 "Network/Pcap/Base.hsc" #-}

{-# LINE 745 "Network/Pcap/Base.hsc" #-}
    | DLT_CHAOS                         -- ^ Chaos

{-# LINE 747 "Network/Pcap/Base.hsc" #-}

{-# LINE 748 "Network/Pcap/Base.hsc" #-}
    | DLT_IEEE802                       -- ^ IEEE 802 networks

{-# LINE 750 "Network/Pcap/Base.hsc" #-}

{-# LINE 751 "Network/Pcap/Base.hsc" #-}
    | DLT_ARCNET                        -- ^ ARCNET

{-# LINE 753 "Network/Pcap/Base.hsc" #-}

{-# LINE 754 "Network/Pcap/Base.hsc" #-}
    | DLT_SLIP                          -- ^ Serial line IP

{-# LINE 756 "Network/Pcap/Base.hsc" #-}

{-# LINE 757 "Network/Pcap/Base.hsc" #-}
    | DLT_PPP                           -- ^ Point-to-point protocol

{-# LINE 759 "Network/Pcap/Base.hsc" #-}

{-# LINE 760 "Network/Pcap/Base.hsc" #-}
    | DLT_FDDI                          -- ^ FDDI

{-# LINE 762 "Network/Pcap/Base.hsc" #-}

{-# LINE 763 "Network/Pcap/Base.hsc" #-}
    | DLT_ATM_RFC1483                   -- ^ LLC SNAP encapsulated ATM

{-# LINE 765 "Network/Pcap/Base.hsc" #-}

{-# LINE 766 "Network/Pcap/Base.hsc" #-}
    | DLT_RAW                           -- ^ raw IP

{-# LINE 768 "Network/Pcap/Base.hsc" #-}

{-# LINE 769 "Network/Pcap/Base.hsc" #-}
    | DLT_SLIP_BSDOS                    -- ^ BSD OS serial line IP

{-# LINE 771 "Network/Pcap/Base.hsc" #-}

{-# LINE 772 "Network/Pcap/Base.hsc" #-}
    | DLT_PPP_BSDOS                     -- ^ BSD OS point-to-point protocol

{-# LINE 774 "Network/Pcap/Base.hsc" #-}

{-# LINE 775 "Network/Pcap/Base.hsc" #-}
    | DLT_ATM_CLIP                      -- ^ Linux classical IP over ATM

{-# LINE 777 "Network/Pcap/Base.hsc" #-}

{-# LINE 778 "Network/Pcap/Base.hsc" #-}
    | DLT_REDBACK_SMARTEDGE             -- ^ Redback SmartEdge 400\/800

{-# LINE 780 "Network/Pcap/Base.hsc" #-}

{-# LINE 781 "Network/Pcap/Base.hsc" #-}
    | DLT_PPP_SERIAL                    -- ^ PPP over serial with HDLC encapsulation

{-# LINE 783 "Network/Pcap/Base.hsc" #-}

{-# LINE 784 "Network/Pcap/Base.hsc" #-}
    | DLT_PPP_ETHER                     -- ^ PPP over ethernet

{-# LINE 786 "Network/Pcap/Base.hsc" #-}

{-# LINE 787 "Network/Pcap/Base.hsc" #-}
    | DLT_SYMANTEC_FIREWALL             -- ^ Symantec Enterprise Firewall

{-# LINE 789 "Network/Pcap/Base.hsc" #-}

{-# LINE 790 "Network/Pcap/Base.hsc" #-}
    | DLT_C_HDLC                        -- ^ Cisco HDLC

{-# LINE 792 "Network/Pcap/Base.hsc" #-}

{-# LINE 793 "Network/Pcap/Base.hsc" #-}
    | DLT_IEEE802_11                    -- ^ IEEE 802.11 wireless

{-# LINE 795 "Network/Pcap/Base.hsc" #-}

{-# LINE 796 "Network/Pcap/Base.hsc" #-}
    | DLT_FRELAY                        -- ^ Frame Relay

{-# LINE 798 "Network/Pcap/Base.hsc" #-}

{-# LINE 799 "Network/Pcap/Base.hsc" #-}
    | DLT_LOOP                          -- ^ OpenBSD loopback device

{-# LINE 801 "Network/Pcap/Base.hsc" #-}

{-# LINE 802 "Network/Pcap/Base.hsc" #-}
    | DLT_ENC                           -- ^ Encapsulated packets for IPsec

{-# LINE 804 "Network/Pcap/Base.hsc" #-}

{-# LINE 805 "Network/Pcap/Base.hsc" #-}
    | DLT_LINUX_SLL                     -- ^ Linux cooked sockets

{-# LINE 807 "Network/Pcap/Base.hsc" #-}

{-# LINE 808 "Network/Pcap/Base.hsc" #-}
    | DLT_LTALK                         -- ^ Apple LocalTalk

{-# LINE 810 "Network/Pcap/Base.hsc" #-}

{-# LINE 811 "Network/Pcap/Base.hsc" #-}
    | DLT_ECONET                        -- ^ Acorn Econet

{-# LINE 813 "Network/Pcap/Base.hsc" #-}

{-# LINE 814 "Network/Pcap/Base.hsc" #-}
    | DLT_IPFILTER                      -- ^ OpenBSD's old ipfilter

{-# LINE 816 "Network/Pcap/Base.hsc" #-}

{-# LINE 817 "Network/Pcap/Base.hsc" #-}
    | DLT_PFLOG                         -- ^ OpenBSD's pflog

{-# LINE 819 "Network/Pcap/Base.hsc" #-}

{-# LINE 820 "Network/Pcap/Base.hsc" #-}
    | DLT_CISCO_IOS                     -- ^ Cisco IOS

{-# LINE 822 "Network/Pcap/Base.hsc" #-}

{-# LINE 823 "Network/Pcap/Base.hsc" #-}
    | DLT_PRISM_HEADER                  -- ^ Intersil Prism II wireless chips

{-# LINE 825 "Network/Pcap/Base.hsc" #-}

{-# LINE 826 "Network/Pcap/Base.hsc" #-}
    | DLT_AIRONET_HEADER                -- ^ Aironet (Cisco) 802.11 wireless

{-# LINE 828 "Network/Pcap/Base.hsc" #-}

{-# LINE 829 "Network/Pcap/Base.hsc" #-}
    | DLT_HHDLC                         -- ^ Siemens HiPath HDLC

{-# LINE 831 "Network/Pcap/Base.hsc" #-}

{-# LINE 832 "Network/Pcap/Base.hsc" #-}
    | DLT_IP_OVER_FC                    -- ^ RFC 2625 IP-over-Fibre Channel

{-# LINE 834 "Network/Pcap/Base.hsc" #-}

{-# LINE 835 "Network/Pcap/Base.hsc" #-}
    | DLT_SUNATM                        -- ^ Full Frontal ATM on Solaris with SunATM

{-# LINE 837 "Network/Pcap/Base.hsc" #-}

{-# LINE 838 "Network/Pcap/Base.hsc" #-}
    | DLT_IEEE802_11_RADIO              -- ^ 802.11 plus a number of bits of link-layer information

{-# LINE 840 "Network/Pcap/Base.hsc" #-}

{-# LINE 841 "Network/Pcap/Base.hsc" #-}
    | DLT_ARCNET_LINUX                  -- ^ Linux ARCNET header

{-# LINE 843 "Network/Pcap/Base.hsc" #-}

{-# LINE 844 "Network/Pcap/Base.hsc" #-}
    | DLT_APPLE_IP_OVER_IEEE1394        -- ^ Apple IP-over-IEEE 1394

{-# LINE 846 "Network/Pcap/Base.hsc" #-}

{-# LINE 847 "Network/Pcap/Base.hsc" #-}
    | DLT_MTP2_WITH_PHDR                -- ^ SS7, C7 MTP2 with pseudo-header

{-# LINE 849 "Network/Pcap/Base.hsc" #-}

{-# LINE 850 "Network/Pcap/Base.hsc" #-}
    | DLT_MTP2                          -- ^ SS7, C7 Message Transfer Part 2 (MPT2)

{-# LINE 852 "Network/Pcap/Base.hsc" #-}

{-# LINE 853 "Network/Pcap/Base.hsc" #-}
    | DLT_MTP3                          -- ^ SS7, C7 Message Transfer Part 3 (MPT3)

{-# LINE 855 "Network/Pcap/Base.hsc" #-}

{-# LINE 856 "Network/Pcap/Base.hsc" #-}
    | DLT_SCCP                          -- ^ SS7, C7 SCCP

{-# LINE 858 "Network/Pcap/Base.hsc" #-}

{-# LINE 859 "Network/Pcap/Base.hsc" #-}
    | DLT_DOCSIS                        -- ^ DOCSIS MAC frame

{-# LINE 861 "Network/Pcap/Base.hsc" #-}

{-# LINE 862 "Network/Pcap/Base.hsc" #-}
    | DLT_LINUX_IRDA                    -- ^ Linux IrDA packet

{-# LINE 864 "Network/Pcap/Base.hsc" #-}

{-# LINE 865 "Network/Pcap/Base.hsc" #-}
    | DLT_USER0                         -- ^ Reserved for private use

{-# LINE 867 "Network/Pcap/Base.hsc" #-}

{-# LINE 868 "Network/Pcap/Base.hsc" #-}
    | DLT_USER1                         -- ^ Reserved for private use

{-# LINE 870 "Network/Pcap/Base.hsc" #-}

{-# LINE 871 "Network/Pcap/Base.hsc" #-}
    | DLT_USER2                         -- ^ Reserved for private use

{-# LINE 873 "Network/Pcap/Base.hsc" #-}

{-# LINE 874 "Network/Pcap/Base.hsc" #-}
    | DLT_USER3                         -- ^ Reserved for private use

{-# LINE 876 "Network/Pcap/Base.hsc" #-}

{-# LINE 877 "Network/Pcap/Base.hsc" #-}
    | DLT_USER4                         -- ^ Reserved for private use

{-# LINE 879 "Network/Pcap/Base.hsc" #-}

{-# LINE 880 "Network/Pcap/Base.hsc" #-}
    | DLT_USER5                         -- ^ Reserved for private use

{-# LINE 882 "Network/Pcap/Base.hsc" #-}

{-# LINE 883 "Network/Pcap/Base.hsc" #-}
    | DLT_USER6                         -- ^ Reserved for private use

{-# LINE 885 "Network/Pcap/Base.hsc" #-}

{-# LINE 886 "Network/Pcap/Base.hsc" #-}
    | DLT_USER7                         -- ^ Reserved for private use

{-# LINE 888 "Network/Pcap/Base.hsc" #-}

{-# LINE 889 "Network/Pcap/Base.hsc" #-}
    | DLT_USER8                         -- ^ Reserved for private use

{-# LINE 891 "Network/Pcap/Base.hsc" #-}

{-# LINE 892 "Network/Pcap/Base.hsc" #-}
    | DLT_USER9                         -- ^ Reserved for private use

{-# LINE 894 "Network/Pcap/Base.hsc" #-}

{-# LINE 895 "Network/Pcap/Base.hsc" #-}
    | DLT_USER10                        -- ^ Reserved for private use

{-# LINE 897 "Network/Pcap/Base.hsc" #-}

{-# LINE 898 "Network/Pcap/Base.hsc" #-}
    | DLT_USER11                        -- ^ Reserved for private use

{-# LINE 900 "Network/Pcap/Base.hsc" #-}

{-# LINE 901 "Network/Pcap/Base.hsc" #-}
    | DLT_USER12                        -- ^ Reserved for private use

{-# LINE 903 "Network/Pcap/Base.hsc" #-}

{-# LINE 904 "Network/Pcap/Base.hsc" #-}
    | DLT_USER13                        -- ^ Reserved for private use

{-# LINE 906 "Network/Pcap/Base.hsc" #-}

{-# LINE 907 "Network/Pcap/Base.hsc" #-}
    | DLT_USER14                        -- ^ Reserved for private use

{-# LINE 909 "Network/Pcap/Base.hsc" #-}

{-# LINE 910 "Network/Pcap/Base.hsc" #-}
    | DLT_USER15                        -- ^ Reserved for private use

{-# LINE 912 "Network/Pcap/Base.hsc" #-}

{-# LINE 913 "Network/Pcap/Base.hsc" #-}
    | DLT_PPP_PPPD                      -- ^ Outgoing packets for ppp daemon

{-# LINE 915 "Network/Pcap/Base.hsc" #-}

{-# LINE 916 "Network/Pcap/Base.hsc" #-}
    | DLT_GPRS_LLC                      -- ^ GPRS LLC

{-# LINE 918 "Network/Pcap/Base.hsc" #-}

{-# LINE 919 "Network/Pcap/Base.hsc" #-}
    | DLT_GPF_T                         -- ^ GPF-T (ITU-T G.7041\/Y.1303)

{-# LINE 921 "Network/Pcap/Base.hsc" #-}

{-# LINE 922 "Network/Pcap/Base.hsc" #-}
    | DLT_GPF_F                         -- ^ GPF-F (ITU-T G.7041\/Y.1303)

{-# LINE 924 "Network/Pcap/Base.hsc" #-}

{-# LINE 925 "Network/Pcap/Base.hsc" #-}
    | DLT_LINUX_LAPD                    -- ^ Raw LAPD for vISDN (/not/ generic LAPD)

{-# LINE 927 "Network/Pcap/Base.hsc" #-}

{-# LINE 928 "Network/Pcap/Base.hsc" #-}
    | DLT_A429                          -- ^ ARINC 429

{-# LINE 930 "Network/Pcap/Base.hsc" #-}

{-# LINE 931 "Network/Pcap/Base.hsc" #-}
    | DLT_A653_ICM                      -- ^ ARINC 653 Interpartition Communication messages

{-# LINE 933 "Network/Pcap/Base.hsc" #-}

{-# LINE 934 "Network/Pcap/Base.hsc" #-}
    | DLT_USB                           -- ^ USB packet

{-# LINE 936 "Network/Pcap/Base.hsc" #-}

{-# LINE 937 "Network/Pcap/Base.hsc" #-}
    | DLT_BLUETOOTH_HCI_H4              -- ^ Bluetooth HCI UART transport layer (part H:4)

{-# LINE 939 "Network/Pcap/Base.hsc" #-}

{-# LINE 940 "Network/Pcap/Base.hsc" #-}
    | DLT_MFR                           -- ^ Multi Link Frame Relay (FRF.16)

{-# LINE 942 "Network/Pcap/Base.hsc" #-}

{-# LINE 943 "Network/Pcap/Base.hsc" #-}
    | DLT_IEEE802_16_MAC_CPS            -- ^ IEEE 802.16 MAC Common Part Sublayer

{-# LINE 945 "Network/Pcap/Base.hsc" #-}

{-# LINE 946 "Network/Pcap/Base.hsc" #-}
    | DLT_USB_LINUX                     -- ^ USB packets, beginning with a Linux USB header

{-# LINE 948 "Network/Pcap/Base.hsc" #-}

{-# LINE 949 "Network/Pcap/Base.hsc" #-}
    | DLT_CAN20B                        -- ^ Controller Area Network (CAN) v2.0B

{-# LINE 951 "Network/Pcap/Base.hsc" #-}

{-# LINE 952 "Network/Pcap/Base.hsc" #-}
    | DLT_IEEE802_15_4_LINUX            -- ^ IEEE 802.15.4, with address fields padded

{-# LINE 954 "Network/Pcap/Base.hsc" #-}

{-# LINE 955 "Network/Pcap/Base.hsc" #-}
    | DLT_PPI                           -- ^ Per Packet Information encapsulated packets

{-# LINE 957 "Network/Pcap/Base.hsc" #-}

{-# LINE 958 "Network/Pcap/Base.hsc" #-}
    | DLT_IEEE802_16_MAC_CPS_RADIO      -- ^ 802.16 MAC Common Part Sublayer with radiotap radio header

{-# LINE 960 "Network/Pcap/Base.hsc" #-}

{-# LINE 961 "Network/Pcap/Base.hsc" #-}
    | DLT_IEEE802_15_4                  -- ^ IEEE 802.15.4, exactly as in the spec

{-# LINE 963 "Network/Pcap/Base.hsc" #-}

{-# LINE 964 "Network/Pcap/Base.hsc" #-}
    | DLT_PFSYNC

{-# LINE 966 "Network/Pcap/Base.hsc" #-}
    deriving (Eq, Ord, Read, Show)

packLink :: Link -> CInt
packLink l = case l of

{-# LINE 971 "Network/Pcap/Base.hsc" #-}
    DLT_NULL -> 0
{-# LINE 972 "Network/Pcap/Base.hsc" #-}

{-# LINE 973 "Network/Pcap/Base.hsc" #-}

{-# LINE 974 "Network/Pcap/Base.hsc" #-}
    DLT_EN10MB -> 1
{-# LINE 975 "Network/Pcap/Base.hsc" #-}

{-# LINE 976 "Network/Pcap/Base.hsc" #-}

{-# LINE 977 "Network/Pcap/Base.hsc" #-}
    DLT_EN3MB -> 2
{-# LINE 978 "Network/Pcap/Base.hsc" #-}

{-# LINE 979 "Network/Pcap/Base.hsc" #-}

{-# LINE 980 "Network/Pcap/Base.hsc" #-}
    DLT_AX25 -> 3
{-# LINE 981 "Network/Pcap/Base.hsc" #-}

{-# LINE 982 "Network/Pcap/Base.hsc" #-}

{-# LINE 983 "Network/Pcap/Base.hsc" #-}
    DLT_PRONET -> 4
{-# LINE 984 "Network/Pcap/Base.hsc" #-}

{-# LINE 985 "Network/Pcap/Base.hsc" #-}

{-# LINE 986 "Network/Pcap/Base.hsc" #-}
    DLT_CHAOS -> 5
{-# LINE 987 "Network/Pcap/Base.hsc" #-}

{-# LINE 988 "Network/Pcap/Base.hsc" #-}

{-# LINE 989 "Network/Pcap/Base.hsc" #-}
    DLT_IEEE802 -> 6
{-# LINE 990 "Network/Pcap/Base.hsc" #-}

{-# LINE 991 "Network/Pcap/Base.hsc" #-}

{-# LINE 992 "Network/Pcap/Base.hsc" #-}
    DLT_ARCNET -> 7
{-# LINE 993 "Network/Pcap/Base.hsc" #-}

{-# LINE 994 "Network/Pcap/Base.hsc" #-}

{-# LINE 995 "Network/Pcap/Base.hsc" #-}
    DLT_SLIP -> 8
{-# LINE 996 "Network/Pcap/Base.hsc" #-}

{-# LINE 997 "Network/Pcap/Base.hsc" #-}

{-# LINE 998 "Network/Pcap/Base.hsc" #-}
    DLT_PPP -> 9
{-# LINE 999 "Network/Pcap/Base.hsc" #-}

{-# LINE 1000 "Network/Pcap/Base.hsc" #-}

{-# LINE 1001 "Network/Pcap/Base.hsc" #-}
    DLT_FDDI -> 10
{-# LINE 1002 "Network/Pcap/Base.hsc" #-}

{-# LINE 1003 "Network/Pcap/Base.hsc" #-}

{-# LINE 1004 "Network/Pcap/Base.hsc" #-}
    DLT_ATM_RFC1483 -> 11
{-# LINE 1005 "Network/Pcap/Base.hsc" #-}

{-# LINE 1006 "Network/Pcap/Base.hsc" #-}

{-# LINE 1007 "Network/Pcap/Base.hsc" #-}
    DLT_RAW -> 12
{-# LINE 1008 "Network/Pcap/Base.hsc" #-}

{-# LINE 1009 "Network/Pcap/Base.hsc" #-}

{-# LINE 1010 "Network/Pcap/Base.hsc" #-}
    DLT_SLIP_BSDOS -> 15
{-# LINE 1011 "Network/Pcap/Base.hsc" #-}

{-# LINE 1012 "Network/Pcap/Base.hsc" #-}

{-# LINE 1013 "Network/Pcap/Base.hsc" #-}
    DLT_PPP_BSDOS -> 16
{-# LINE 1014 "Network/Pcap/Base.hsc" #-}

{-# LINE 1015 "Network/Pcap/Base.hsc" #-}

{-# LINE 1016 "Network/Pcap/Base.hsc" #-}
    DLT_ATM_CLIP -> 19
{-# LINE 1017 "Network/Pcap/Base.hsc" #-}

{-# LINE 1018 "Network/Pcap/Base.hsc" #-}

{-# LINE 1019 "Network/Pcap/Base.hsc" #-}
    DLT_REDBACK_SMARTEDGE -> 32
{-# LINE 1020 "Network/Pcap/Base.hsc" #-}

{-# LINE 1021 "Network/Pcap/Base.hsc" #-}

{-# LINE 1022 "Network/Pcap/Base.hsc" #-}
    DLT_PPP_SERIAL -> 50
{-# LINE 1023 "Network/Pcap/Base.hsc" #-}

{-# LINE 1024 "Network/Pcap/Base.hsc" #-}

{-# LINE 1025 "Network/Pcap/Base.hsc" #-}
    DLT_PPP_ETHER -> 51
{-# LINE 1026 "Network/Pcap/Base.hsc" #-}

{-# LINE 1027 "Network/Pcap/Base.hsc" #-}

{-# LINE 1028 "Network/Pcap/Base.hsc" #-}
    DLT_SYMANTEC_FIREWALL -> 99
{-# LINE 1029 "Network/Pcap/Base.hsc" #-}

{-# LINE 1030 "Network/Pcap/Base.hsc" #-}

{-# LINE 1031 "Network/Pcap/Base.hsc" #-}
    DLT_C_HDLC -> 104
{-# LINE 1032 "Network/Pcap/Base.hsc" #-}

{-# LINE 1033 "Network/Pcap/Base.hsc" #-}

{-# LINE 1034 "Network/Pcap/Base.hsc" #-}
    DLT_IEEE802_11 -> 105
{-# LINE 1035 "Network/Pcap/Base.hsc" #-}

{-# LINE 1036 "Network/Pcap/Base.hsc" #-}

{-# LINE 1037 "Network/Pcap/Base.hsc" #-}
    DLT_FRELAY -> 107
{-# LINE 1038 "Network/Pcap/Base.hsc" #-}

{-# LINE 1039 "Network/Pcap/Base.hsc" #-}

{-# LINE 1040 "Network/Pcap/Base.hsc" #-}
    DLT_LOOP -> 108
{-# LINE 1041 "Network/Pcap/Base.hsc" #-}

{-# LINE 1042 "Network/Pcap/Base.hsc" #-}

{-# LINE 1043 "Network/Pcap/Base.hsc" #-}
    DLT_ENC -> 109
{-# LINE 1044 "Network/Pcap/Base.hsc" #-}

{-# LINE 1045 "Network/Pcap/Base.hsc" #-}

{-# LINE 1046 "Network/Pcap/Base.hsc" #-}
    DLT_LINUX_SLL -> 113
{-# LINE 1047 "Network/Pcap/Base.hsc" #-}

{-# LINE 1048 "Network/Pcap/Base.hsc" #-}

{-# LINE 1049 "Network/Pcap/Base.hsc" #-}
    DLT_LTALK -> 114
{-# LINE 1050 "Network/Pcap/Base.hsc" #-}

{-# LINE 1051 "Network/Pcap/Base.hsc" #-}

{-# LINE 1052 "Network/Pcap/Base.hsc" #-}
    DLT_ECONET -> 115
{-# LINE 1053 "Network/Pcap/Base.hsc" #-}

{-# LINE 1054 "Network/Pcap/Base.hsc" #-}

{-# LINE 1055 "Network/Pcap/Base.hsc" #-}
    DLT_IPFILTER -> 116
{-# LINE 1056 "Network/Pcap/Base.hsc" #-}

{-# LINE 1057 "Network/Pcap/Base.hsc" #-}

{-# LINE 1060 "Network/Pcap/Base.hsc" #-}

{-# LINE 1061 "Network/Pcap/Base.hsc" #-}
    DLT_PFSYNC -> 246
{-# LINE 1062 "Network/Pcap/Base.hsc" #-}

{-# LINE 1063 "Network/Pcap/Base.hsc" #-}

{-# LINE 1064 "Network/Pcap/Base.hsc" #-}
    DLT_PFLOG -> 117
{-# LINE 1065 "Network/Pcap/Base.hsc" #-}

{-# LINE 1066 "Network/Pcap/Base.hsc" #-}

{-# LINE 1067 "Network/Pcap/Base.hsc" #-}
    DLT_CISCO_IOS -> 118
{-# LINE 1068 "Network/Pcap/Base.hsc" #-}

{-# LINE 1069 "Network/Pcap/Base.hsc" #-}

{-# LINE 1070 "Network/Pcap/Base.hsc" #-}
    DLT_PRISM_HEADER -> 119
{-# LINE 1071 "Network/Pcap/Base.hsc" #-}

{-# LINE 1072 "Network/Pcap/Base.hsc" #-}

{-# LINE 1073 "Network/Pcap/Base.hsc" #-}
    DLT_AIRONET_HEADER -> 120
{-# LINE 1074 "Network/Pcap/Base.hsc" #-}

{-# LINE 1075 "Network/Pcap/Base.hsc" #-}

{-# LINE 1076 "Network/Pcap/Base.hsc" #-}
    DLT_HHDLC -> 121
{-# LINE 1077 "Network/Pcap/Base.hsc" #-}

{-# LINE 1078 "Network/Pcap/Base.hsc" #-}

{-# LINE 1079 "Network/Pcap/Base.hsc" #-}
    DLT_IP_OVER_FC -> 122
{-# LINE 1080 "Network/Pcap/Base.hsc" #-}

{-# LINE 1081 "Network/Pcap/Base.hsc" #-}

{-# LINE 1082 "Network/Pcap/Base.hsc" #-}
    DLT_SUNATM -> 123
{-# LINE 1083 "Network/Pcap/Base.hsc" #-}

{-# LINE 1084 "Network/Pcap/Base.hsc" #-}

{-# LINE 1085 "Network/Pcap/Base.hsc" #-}
    DLT_IEEE802_11_RADIO -> 127
{-# LINE 1086 "Network/Pcap/Base.hsc" #-}

{-# LINE 1087 "Network/Pcap/Base.hsc" #-}

{-# LINE 1088 "Network/Pcap/Base.hsc" #-}
    DLT_ARCNET_LINUX -> 129
{-# LINE 1089 "Network/Pcap/Base.hsc" #-}

{-# LINE 1090 "Network/Pcap/Base.hsc" #-}

{-# LINE 1091 "Network/Pcap/Base.hsc" #-}
    DLT_APPLE_IP_OVER_IEEE1394 -> 138
{-# LINE 1092 "Network/Pcap/Base.hsc" #-}

{-# LINE 1093 "Network/Pcap/Base.hsc" #-}

{-# LINE 1094 "Network/Pcap/Base.hsc" #-}
    DLT_MTP2_WITH_PHDR -> 139
{-# LINE 1095 "Network/Pcap/Base.hsc" #-}

{-# LINE 1096 "Network/Pcap/Base.hsc" #-}

{-# LINE 1097 "Network/Pcap/Base.hsc" #-}
    DLT_MTP2 -> 140
{-# LINE 1098 "Network/Pcap/Base.hsc" #-}

{-# LINE 1099 "Network/Pcap/Base.hsc" #-}

{-# LINE 1100 "Network/Pcap/Base.hsc" #-}
    DLT_MTP3 -> 141
{-# LINE 1101 "Network/Pcap/Base.hsc" #-}

{-# LINE 1102 "Network/Pcap/Base.hsc" #-}

{-# LINE 1103 "Network/Pcap/Base.hsc" #-}
    DLT_SCCP -> 142
{-# LINE 1104 "Network/Pcap/Base.hsc" #-}

{-# LINE 1105 "Network/Pcap/Base.hsc" #-}

{-# LINE 1106 "Network/Pcap/Base.hsc" #-}
    DLT_DOCSIS -> 143
{-# LINE 1107 "Network/Pcap/Base.hsc" #-}

{-# LINE 1108 "Network/Pcap/Base.hsc" #-}

{-# LINE 1109 "Network/Pcap/Base.hsc" #-}
    DLT_LINUX_IRDA -> 144
{-# LINE 1110 "Network/Pcap/Base.hsc" #-}

{-# LINE 1111 "Network/Pcap/Base.hsc" #-}

{-# LINE 1112 "Network/Pcap/Base.hsc" #-}
    DLT_USER0 -> 147
{-# LINE 1113 "Network/Pcap/Base.hsc" #-}

{-# LINE 1114 "Network/Pcap/Base.hsc" #-}

{-# LINE 1115 "Network/Pcap/Base.hsc" #-}
    DLT_USER1 -> 148
{-# LINE 1116 "Network/Pcap/Base.hsc" #-}

{-# LINE 1117 "Network/Pcap/Base.hsc" #-}

{-# LINE 1118 "Network/Pcap/Base.hsc" #-}
    DLT_USER2 -> 149
{-# LINE 1119 "Network/Pcap/Base.hsc" #-}

{-# LINE 1120 "Network/Pcap/Base.hsc" #-}

{-# LINE 1121 "Network/Pcap/Base.hsc" #-}
    DLT_USER3 -> 150
{-# LINE 1122 "Network/Pcap/Base.hsc" #-}

{-# LINE 1123 "Network/Pcap/Base.hsc" #-}

{-# LINE 1124 "Network/Pcap/Base.hsc" #-}
    DLT_USER4 -> 151
{-# LINE 1125 "Network/Pcap/Base.hsc" #-}

{-# LINE 1126 "Network/Pcap/Base.hsc" #-}

{-# LINE 1127 "Network/Pcap/Base.hsc" #-}
    DLT_USER5 -> 152
{-# LINE 1128 "Network/Pcap/Base.hsc" #-}

{-# LINE 1129 "Network/Pcap/Base.hsc" #-}

{-# LINE 1130 "Network/Pcap/Base.hsc" #-}
    DLT_USER6 -> 153
{-# LINE 1131 "Network/Pcap/Base.hsc" #-}

{-# LINE 1132 "Network/Pcap/Base.hsc" #-}

{-# LINE 1133 "Network/Pcap/Base.hsc" #-}
    DLT_USER7 -> 154
{-# LINE 1134 "Network/Pcap/Base.hsc" #-}

{-# LINE 1135 "Network/Pcap/Base.hsc" #-}

{-# LINE 1136 "Network/Pcap/Base.hsc" #-}
    DLT_USER8 -> 155
{-# LINE 1137 "Network/Pcap/Base.hsc" #-}

{-# LINE 1138 "Network/Pcap/Base.hsc" #-}

{-# LINE 1139 "Network/Pcap/Base.hsc" #-}
    DLT_USER9 -> 156
{-# LINE 1140 "Network/Pcap/Base.hsc" #-}

{-# LINE 1141 "Network/Pcap/Base.hsc" #-}

{-# LINE 1142 "Network/Pcap/Base.hsc" #-}
    DLT_USER10 -> 157
{-# LINE 1143 "Network/Pcap/Base.hsc" #-}

{-# LINE 1144 "Network/Pcap/Base.hsc" #-}

{-# LINE 1145 "Network/Pcap/Base.hsc" #-}
    DLT_USER11 -> 158
{-# LINE 1146 "Network/Pcap/Base.hsc" #-}

{-# LINE 1147 "Network/Pcap/Base.hsc" #-}

{-# LINE 1148 "Network/Pcap/Base.hsc" #-}
    DLT_USER12 -> 159
{-# LINE 1149 "Network/Pcap/Base.hsc" #-}

{-# LINE 1150 "Network/Pcap/Base.hsc" #-}

{-# LINE 1151 "Network/Pcap/Base.hsc" #-}
    DLT_USER13 -> 160
{-# LINE 1152 "Network/Pcap/Base.hsc" #-}

{-# LINE 1153 "Network/Pcap/Base.hsc" #-}

{-# LINE 1154 "Network/Pcap/Base.hsc" #-}
    DLT_USER14 -> 161
{-# LINE 1155 "Network/Pcap/Base.hsc" #-}

{-# LINE 1156 "Network/Pcap/Base.hsc" #-}

{-# LINE 1157 "Network/Pcap/Base.hsc" #-}
    DLT_USER15 -> 162
{-# LINE 1158 "Network/Pcap/Base.hsc" #-}

{-# LINE 1159 "Network/Pcap/Base.hsc" #-}

{-# LINE 1160 "Network/Pcap/Base.hsc" #-}
    DLT_PPP_PPPD -> 166
{-# LINE 1161 "Network/Pcap/Base.hsc" #-}

{-# LINE 1162 "Network/Pcap/Base.hsc" #-}

{-# LINE 1163 "Network/Pcap/Base.hsc" #-}
    DLT_GPRS_LLC -> 169
{-# LINE 1164 "Network/Pcap/Base.hsc" #-}

{-# LINE 1165 "Network/Pcap/Base.hsc" #-}

{-# LINE 1166 "Network/Pcap/Base.hsc" #-}
    DLT_GPF_T -> 170
{-# LINE 1167 "Network/Pcap/Base.hsc" #-}

{-# LINE 1168 "Network/Pcap/Base.hsc" #-}

{-# LINE 1169 "Network/Pcap/Base.hsc" #-}
    DLT_GPF_F -> 171
{-# LINE 1170 "Network/Pcap/Base.hsc" #-}

{-# LINE 1171 "Network/Pcap/Base.hsc" #-}

{-# LINE 1172 "Network/Pcap/Base.hsc" #-}
    DLT_LINUX_LAPD -> 177
{-# LINE 1173 "Network/Pcap/Base.hsc" #-}

{-# LINE 1174 "Network/Pcap/Base.hsc" #-}

{-# LINE 1175 "Network/Pcap/Base.hsc" #-}
    DLT_MFR -> 182
{-# LINE 1176 "Network/Pcap/Base.hsc" #-}

{-# LINE 1177 "Network/Pcap/Base.hsc" #-}

{-# LINE 1178 "Network/Pcap/Base.hsc" #-}
    DLT_A429 -> 184
{-# LINE 1179 "Network/Pcap/Base.hsc" #-}

{-# LINE 1180 "Network/Pcap/Base.hsc" #-}

{-# LINE 1181 "Network/Pcap/Base.hsc" #-}
    DLT_A653_ICM -> 185
{-# LINE 1182 "Network/Pcap/Base.hsc" #-}

{-# LINE 1183 "Network/Pcap/Base.hsc" #-}

{-# LINE 1184 "Network/Pcap/Base.hsc" #-}
    DLT_USB -> 186
{-# LINE 1185 "Network/Pcap/Base.hsc" #-}

{-# LINE 1186 "Network/Pcap/Base.hsc" #-}

{-# LINE 1187 "Network/Pcap/Base.hsc" #-}
    DLT_BLUETOOTH_HCI_H4 -> 187
{-# LINE 1188 "Network/Pcap/Base.hsc" #-}

{-# LINE 1189 "Network/Pcap/Base.hsc" #-}

{-# LINE 1190 "Network/Pcap/Base.hsc" #-}
    DLT_IEEE802_16_MAC_CPS -> 188
{-# LINE 1191 "Network/Pcap/Base.hsc" #-}

{-# LINE 1192 "Network/Pcap/Base.hsc" #-}

{-# LINE 1193 "Network/Pcap/Base.hsc" #-}
    DLT_USB_LINUX -> 189
{-# LINE 1194 "Network/Pcap/Base.hsc" #-}

{-# LINE 1195 "Network/Pcap/Base.hsc" #-}

{-# LINE 1196 "Network/Pcap/Base.hsc" #-}
    DLT_CAN20B -> 190
{-# LINE 1197 "Network/Pcap/Base.hsc" #-}

{-# LINE 1198 "Network/Pcap/Base.hsc" #-}

{-# LINE 1199 "Network/Pcap/Base.hsc" #-}
    DLT_IEEE802_15_4_LINUX -> 191
{-# LINE 1200 "Network/Pcap/Base.hsc" #-}

{-# LINE 1201 "Network/Pcap/Base.hsc" #-}

{-# LINE 1202 "Network/Pcap/Base.hsc" #-}
    DLT_PPI -> 192
{-# LINE 1203 "Network/Pcap/Base.hsc" #-}

{-# LINE 1204 "Network/Pcap/Base.hsc" #-}

{-# LINE 1205 "Network/Pcap/Base.hsc" #-}
    DLT_IEEE802_16_MAC_CPS_RADIO -> 193
{-# LINE 1206 "Network/Pcap/Base.hsc" #-}

{-# LINE 1207 "Network/Pcap/Base.hsc" #-}

{-# LINE 1208 "Network/Pcap/Base.hsc" #-}
    DLT_IEEE802_15_4 -> 195
{-# LINE 1209 "Network/Pcap/Base.hsc" #-}

{-# LINE 1210 "Network/Pcap/Base.hsc" #-}

{-# LINE 1211 "Network/Pcap/Base.hsc" #-}
    DLT_UNKNOWN _ -> error "cannot pack unknown link type"

{-# LINE 1213 "Network/Pcap/Base.hsc" #-}

unpackLink :: CInt -> Link
unpackLink l = case l of

{-# LINE 1217 "Network/Pcap/Base.hsc" #-}
    (0) -> DLT_NULL
{-# LINE 1218 "Network/Pcap/Base.hsc" #-}

{-# LINE 1219 "Network/Pcap/Base.hsc" #-}

{-# LINE 1220 "Network/Pcap/Base.hsc" #-}
    (1) -> DLT_EN10MB
{-# LINE 1221 "Network/Pcap/Base.hsc" #-}

{-# LINE 1222 "Network/Pcap/Base.hsc" #-}

{-# LINE 1223 "Network/Pcap/Base.hsc" #-}
    (2) -> DLT_EN3MB
{-# LINE 1224 "Network/Pcap/Base.hsc" #-}

{-# LINE 1225 "Network/Pcap/Base.hsc" #-}

{-# LINE 1226 "Network/Pcap/Base.hsc" #-}
    (3) -> DLT_AX25
{-# LINE 1227 "Network/Pcap/Base.hsc" #-}

{-# LINE 1228 "Network/Pcap/Base.hsc" #-}

{-# LINE 1229 "Network/Pcap/Base.hsc" #-}
    (4) -> DLT_PRONET
{-# LINE 1230 "Network/Pcap/Base.hsc" #-}

{-# LINE 1231 "Network/Pcap/Base.hsc" #-}

{-# LINE 1232 "Network/Pcap/Base.hsc" #-}
    (5) -> DLT_CHAOS
{-# LINE 1233 "Network/Pcap/Base.hsc" #-}

{-# LINE 1234 "Network/Pcap/Base.hsc" #-}

{-# LINE 1235 "Network/Pcap/Base.hsc" #-}
    (6) -> DLT_IEEE802
{-# LINE 1236 "Network/Pcap/Base.hsc" #-}

{-# LINE 1237 "Network/Pcap/Base.hsc" #-}

{-# LINE 1238 "Network/Pcap/Base.hsc" #-}
    (7) -> DLT_ARCNET
{-# LINE 1239 "Network/Pcap/Base.hsc" #-}

{-# LINE 1240 "Network/Pcap/Base.hsc" #-}

{-# LINE 1241 "Network/Pcap/Base.hsc" #-}
    (8) -> DLT_SLIP
{-# LINE 1242 "Network/Pcap/Base.hsc" #-}

{-# LINE 1243 "Network/Pcap/Base.hsc" #-}

{-# LINE 1244 "Network/Pcap/Base.hsc" #-}
    (9) -> DLT_PPP
{-# LINE 1245 "Network/Pcap/Base.hsc" #-}

{-# LINE 1246 "Network/Pcap/Base.hsc" #-}

{-# LINE 1247 "Network/Pcap/Base.hsc" #-}
    (10) -> DLT_FDDI
{-# LINE 1248 "Network/Pcap/Base.hsc" #-}

{-# LINE 1249 "Network/Pcap/Base.hsc" #-}

{-# LINE 1250 "Network/Pcap/Base.hsc" #-}
    (11) -> DLT_ATM_RFC1483
{-# LINE 1251 "Network/Pcap/Base.hsc" #-}

{-# LINE 1252 "Network/Pcap/Base.hsc" #-}

{-# LINE 1253 "Network/Pcap/Base.hsc" #-}
    (12) -> DLT_RAW
{-# LINE 1254 "Network/Pcap/Base.hsc" #-}

{-# LINE 1255 "Network/Pcap/Base.hsc" #-}

{-# LINE 1256 "Network/Pcap/Base.hsc" #-}
    (15) -> DLT_SLIP_BSDOS
{-# LINE 1257 "Network/Pcap/Base.hsc" #-}

{-# LINE 1258 "Network/Pcap/Base.hsc" #-}

{-# LINE 1259 "Network/Pcap/Base.hsc" #-}
    (16) -> DLT_PPP_BSDOS
{-# LINE 1260 "Network/Pcap/Base.hsc" #-}

{-# LINE 1261 "Network/Pcap/Base.hsc" #-}

{-# LINE 1262 "Network/Pcap/Base.hsc" #-}
    (19) -> DLT_ATM_CLIP
{-# LINE 1263 "Network/Pcap/Base.hsc" #-}

{-# LINE 1264 "Network/Pcap/Base.hsc" #-}

{-# LINE 1265 "Network/Pcap/Base.hsc" #-}
    (32) -> DLT_REDBACK_SMARTEDGE
{-# LINE 1266 "Network/Pcap/Base.hsc" #-}

{-# LINE 1267 "Network/Pcap/Base.hsc" #-}

{-# LINE 1268 "Network/Pcap/Base.hsc" #-}
    (50) -> DLT_PPP_SERIAL
{-# LINE 1269 "Network/Pcap/Base.hsc" #-}

{-# LINE 1270 "Network/Pcap/Base.hsc" #-}

{-# LINE 1271 "Network/Pcap/Base.hsc" #-}
    (51) -> DLT_PPP_ETHER
{-# LINE 1272 "Network/Pcap/Base.hsc" #-}

{-# LINE 1273 "Network/Pcap/Base.hsc" #-}

{-# LINE 1274 "Network/Pcap/Base.hsc" #-}
    (99) -> DLT_SYMANTEC_FIREWALL
{-# LINE 1275 "Network/Pcap/Base.hsc" #-}

{-# LINE 1276 "Network/Pcap/Base.hsc" #-}

{-# LINE 1277 "Network/Pcap/Base.hsc" #-}
    (104) -> DLT_C_HDLC
{-# LINE 1278 "Network/Pcap/Base.hsc" #-}

{-# LINE 1279 "Network/Pcap/Base.hsc" #-}

{-# LINE 1280 "Network/Pcap/Base.hsc" #-}
    (105) -> DLT_IEEE802_11
{-# LINE 1281 "Network/Pcap/Base.hsc" #-}

{-# LINE 1282 "Network/Pcap/Base.hsc" #-}

{-# LINE 1283 "Network/Pcap/Base.hsc" #-}
    (107) -> DLT_FRELAY
{-# LINE 1284 "Network/Pcap/Base.hsc" #-}

{-# LINE 1285 "Network/Pcap/Base.hsc" #-}

{-# LINE 1286 "Network/Pcap/Base.hsc" #-}
    (108) -> DLT_LOOP
{-# LINE 1287 "Network/Pcap/Base.hsc" #-}

{-# LINE 1288 "Network/Pcap/Base.hsc" #-}

{-# LINE 1289 "Network/Pcap/Base.hsc" #-}
    (109) -> DLT_ENC
{-# LINE 1290 "Network/Pcap/Base.hsc" #-}

{-# LINE 1291 "Network/Pcap/Base.hsc" #-}

{-# LINE 1292 "Network/Pcap/Base.hsc" #-}
    (113) -> DLT_LINUX_SLL
{-# LINE 1293 "Network/Pcap/Base.hsc" #-}

{-# LINE 1294 "Network/Pcap/Base.hsc" #-}

{-# LINE 1295 "Network/Pcap/Base.hsc" #-}
    (114) -> DLT_LTALK
{-# LINE 1296 "Network/Pcap/Base.hsc" #-}

{-# LINE 1297 "Network/Pcap/Base.hsc" #-}

{-# LINE 1298 "Network/Pcap/Base.hsc" #-}
    (115) -> DLT_ECONET
{-# LINE 1299 "Network/Pcap/Base.hsc" #-}

{-# LINE 1300 "Network/Pcap/Base.hsc" #-}

{-# LINE 1301 "Network/Pcap/Base.hsc" #-}
    (116) -> DLT_IPFILTER
{-# LINE 1302 "Network/Pcap/Base.hsc" #-}

{-# LINE 1303 "Network/Pcap/Base.hsc" #-}

{-# LINE 1306 "Network/Pcap/Base.hsc" #-}

{-# LINE 1307 "Network/Pcap/Base.hsc" #-}
    (246) -> DLT_PFSYNC
{-# LINE 1308 "Network/Pcap/Base.hsc" #-}

{-# LINE 1309 "Network/Pcap/Base.hsc" #-}

{-# LINE 1310 "Network/Pcap/Base.hsc" #-}
    (117) -> DLT_PFLOG
{-# LINE 1311 "Network/Pcap/Base.hsc" #-}

{-# LINE 1312 "Network/Pcap/Base.hsc" #-}

{-# LINE 1313 "Network/Pcap/Base.hsc" #-}
    (118) -> DLT_CISCO_IOS
{-# LINE 1314 "Network/Pcap/Base.hsc" #-}

{-# LINE 1315 "Network/Pcap/Base.hsc" #-}

{-# LINE 1316 "Network/Pcap/Base.hsc" #-}
    (119) -> DLT_PRISM_HEADER
{-# LINE 1317 "Network/Pcap/Base.hsc" #-}

{-# LINE 1318 "Network/Pcap/Base.hsc" #-}

{-# LINE 1319 "Network/Pcap/Base.hsc" #-}
    (120) -> DLT_AIRONET_HEADER
{-# LINE 1320 "Network/Pcap/Base.hsc" #-}

{-# LINE 1321 "Network/Pcap/Base.hsc" #-}

{-# LINE 1322 "Network/Pcap/Base.hsc" #-}
    (121) -> DLT_HHDLC
{-# LINE 1323 "Network/Pcap/Base.hsc" #-}

{-# LINE 1324 "Network/Pcap/Base.hsc" #-}

{-# LINE 1325 "Network/Pcap/Base.hsc" #-}
    (122) -> DLT_IP_OVER_FC
{-# LINE 1326 "Network/Pcap/Base.hsc" #-}

{-# LINE 1327 "Network/Pcap/Base.hsc" #-}

{-# LINE 1328 "Network/Pcap/Base.hsc" #-}
    (123) -> DLT_SUNATM
{-# LINE 1329 "Network/Pcap/Base.hsc" #-}

{-# LINE 1330 "Network/Pcap/Base.hsc" #-}

{-# LINE 1331 "Network/Pcap/Base.hsc" #-}
    (127) -> DLT_IEEE802_11_RADIO
{-# LINE 1332 "Network/Pcap/Base.hsc" #-}

{-# LINE 1333 "Network/Pcap/Base.hsc" #-}

{-# LINE 1334 "Network/Pcap/Base.hsc" #-}
    (129) -> DLT_ARCNET_LINUX
{-# LINE 1335 "Network/Pcap/Base.hsc" #-}

{-# LINE 1336 "Network/Pcap/Base.hsc" #-}

{-# LINE 1337 "Network/Pcap/Base.hsc" #-}
    (138) -> DLT_APPLE_IP_OVER_IEEE1394
{-# LINE 1338 "Network/Pcap/Base.hsc" #-}

{-# LINE 1339 "Network/Pcap/Base.hsc" #-}

{-# LINE 1340 "Network/Pcap/Base.hsc" #-}
    (139) -> DLT_MTP2_WITH_PHDR
{-# LINE 1341 "Network/Pcap/Base.hsc" #-}

{-# LINE 1342 "Network/Pcap/Base.hsc" #-}

{-# LINE 1343 "Network/Pcap/Base.hsc" #-}
    (140) -> DLT_MTP2
{-# LINE 1344 "Network/Pcap/Base.hsc" #-}

{-# LINE 1345 "Network/Pcap/Base.hsc" #-}

{-# LINE 1346 "Network/Pcap/Base.hsc" #-}
    (141) -> DLT_MTP3
{-# LINE 1347 "Network/Pcap/Base.hsc" #-}

{-# LINE 1348 "Network/Pcap/Base.hsc" #-}

{-# LINE 1349 "Network/Pcap/Base.hsc" #-}
    (142) -> DLT_SCCP
{-# LINE 1350 "Network/Pcap/Base.hsc" #-}

{-# LINE 1351 "Network/Pcap/Base.hsc" #-}

{-# LINE 1352 "Network/Pcap/Base.hsc" #-}
    (143) -> DLT_DOCSIS
{-# LINE 1353 "Network/Pcap/Base.hsc" #-}

{-# LINE 1354 "Network/Pcap/Base.hsc" #-}

{-# LINE 1355 "Network/Pcap/Base.hsc" #-}
    (144) -> DLT_LINUX_IRDA
{-# LINE 1356 "Network/Pcap/Base.hsc" #-}

{-# LINE 1357 "Network/Pcap/Base.hsc" #-}

{-# LINE 1358 "Network/Pcap/Base.hsc" #-}
    (147) -> DLT_USER0
{-# LINE 1359 "Network/Pcap/Base.hsc" #-}

{-# LINE 1360 "Network/Pcap/Base.hsc" #-}

{-# LINE 1361 "Network/Pcap/Base.hsc" #-}
    (148) -> DLT_USER1
{-# LINE 1362 "Network/Pcap/Base.hsc" #-}

{-# LINE 1363 "Network/Pcap/Base.hsc" #-}

{-# LINE 1364 "Network/Pcap/Base.hsc" #-}
    (149) -> DLT_USER2
{-# LINE 1365 "Network/Pcap/Base.hsc" #-}

{-# LINE 1366 "Network/Pcap/Base.hsc" #-}

{-# LINE 1367 "Network/Pcap/Base.hsc" #-}
    (150) -> DLT_USER3
{-# LINE 1368 "Network/Pcap/Base.hsc" #-}

{-# LINE 1369 "Network/Pcap/Base.hsc" #-}

{-# LINE 1370 "Network/Pcap/Base.hsc" #-}
    (151) -> DLT_USER4
{-# LINE 1371 "Network/Pcap/Base.hsc" #-}

{-# LINE 1372 "Network/Pcap/Base.hsc" #-}

{-# LINE 1373 "Network/Pcap/Base.hsc" #-}
    (152) -> DLT_USER5
{-# LINE 1374 "Network/Pcap/Base.hsc" #-}

{-# LINE 1375 "Network/Pcap/Base.hsc" #-}

{-# LINE 1376 "Network/Pcap/Base.hsc" #-}
    (153) -> DLT_USER6
{-# LINE 1377 "Network/Pcap/Base.hsc" #-}

{-# LINE 1378 "Network/Pcap/Base.hsc" #-}

{-# LINE 1379 "Network/Pcap/Base.hsc" #-}
    (154) -> DLT_USER7
{-# LINE 1380 "Network/Pcap/Base.hsc" #-}

{-# LINE 1381 "Network/Pcap/Base.hsc" #-}

{-# LINE 1382 "Network/Pcap/Base.hsc" #-}
    (155) -> DLT_USER8
{-# LINE 1383 "Network/Pcap/Base.hsc" #-}

{-# LINE 1384 "Network/Pcap/Base.hsc" #-}

{-# LINE 1385 "Network/Pcap/Base.hsc" #-}
    (156) -> DLT_USER9
{-# LINE 1386 "Network/Pcap/Base.hsc" #-}

{-# LINE 1387 "Network/Pcap/Base.hsc" #-}

{-# LINE 1388 "Network/Pcap/Base.hsc" #-}
    (157) -> DLT_USER10
{-# LINE 1389 "Network/Pcap/Base.hsc" #-}

{-# LINE 1390 "Network/Pcap/Base.hsc" #-}

{-# LINE 1391 "Network/Pcap/Base.hsc" #-}
    (158) -> DLT_USER11
{-# LINE 1392 "Network/Pcap/Base.hsc" #-}

{-# LINE 1393 "Network/Pcap/Base.hsc" #-}

{-# LINE 1394 "Network/Pcap/Base.hsc" #-}
    (159) -> DLT_USER12
{-# LINE 1395 "Network/Pcap/Base.hsc" #-}

{-# LINE 1396 "Network/Pcap/Base.hsc" #-}

{-# LINE 1397 "Network/Pcap/Base.hsc" #-}
    (160) -> DLT_USER13
{-# LINE 1398 "Network/Pcap/Base.hsc" #-}

{-# LINE 1399 "Network/Pcap/Base.hsc" #-}

{-# LINE 1400 "Network/Pcap/Base.hsc" #-}
    (161) -> DLT_USER14
{-# LINE 1401 "Network/Pcap/Base.hsc" #-}

{-# LINE 1402 "Network/Pcap/Base.hsc" #-}

{-# LINE 1403 "Network/Pcap/Base.hsc" #-}
    (162) -> DLT_USER15
{-# LINE 1404 "Network/Pcap/Base.hsc" #-}

{-# LINE 1405 "Network/Pcap/Base.hsc" #-}

{-# LINE 1406 "Network/Pcap/Base.hsc" #-}
    (166) -> DLT_PPP_PPPD
{-# LINE 1407 "Network/Pcap/Base.hsc" #-}

{-# LINE 1408 "Network/Pcap/Base.hsc" #-}

{-# LINE 1409 "Network/Pcap/Base.hsc" #-}
    (169) -> DLT_GPRS_LLC
{-# LINE 1410 "Network/Pcap/Base.hsc" #-}

{-# LINE 1411 "Network/Pcap/Base.hsc" #-}

{-# LINE 1412 "Network/Pcap/Base.hsc" #-}
    (170) -> DLT_GPF_T
{-# LINE 1413 "Network/Pcap/Base.hsc" #-}

{-# LINE 1414 "Network/Pcap/Base.hsc" #-}

{-# LINE 1415 "Network/Pcap/Base.hsc" #-}
    (171) -> DLT_GPF_F
{-# LINE 1416 "Network/Pcap/Base.hsc" #-}

{-# LINE 1417 "Network/Pcap/Base.hsc" #-}

{-# LINE 1418 "Network/Pcap/Base.hsc" #-}
    (177) -> DLT_LINUX_LAPD
{-# LINE 1419 "Network/Pcap/Base.hsc" #-}

{-# LINE 1420 "Network/Pcap/Base.hsc" #-}

{-# LINE 1421 "Network/Pcap/Base.hsc" #-}
    (182) -> DLT_MFR
{-# LINE 1422 "Network/Pcap/Base.hsc" #-}

{-# LINE 1423 "Network/Pcap/Base.hsc" #-}

{-# LINE 1424 "Network/Pcap/Base.hsc" #-}
    (184) -> DLT_A429
{-# LINE 1425 "Network/Pcap/Base.hsc" #-}

{-# LINE 1426 "Network/Pcap/Base.hsc" #-}

{-# LINE 1427 "Network/Pcap/Base.hsc" #-}
    (185) -> DLT_A653_ICM
{-# LINE 1428 "Network/Pcap/Base.hsc" #-}

{-# LINE 1429 "Network/Pcap/Base.hsc" #-}

{-# LINE 1430 "Network/Pcap/Base.hsc" #-}
    (186) -> DLT_USB
{-# LINE 1431 "Network/Pcap/Base.hsc" #-}

{-# LINE 1432 "Network/Pcap/Base.hsc" #-}

{-# LINE 1433 "Network/Pcap/Base.hsc" #-}
    (187) -> DLT_BLUETOOTH_HCI_H4
{-# LINE 1434 "Network/Pcap/Base.hsc" #-}

{-# LINE 1435 "Network/Pcap/Base.hsc" #-}

{-# LINE 1436 "Network/Pcap/Base.hsc" #-}
    (188) -> DLT_IEEE802_16_MAC_CPS
{-# LINE 1437 "Network/Pcap/Base.hsc" #-}

{-# LINE 1438 "Network/Pcap/Base.hsc" #-}

{-# LINE 1439 "Network/Pcap/Base.hsc" #-}
    (189) -> DLT_USB_LINUX
{-# LINE 1440 "Network/Pcap/Base.hsc" #-}

{-# LINE 1441 "Network/Pcap/Base.hsc" #-}

{-# LINE 1442 "Network/Pcap/Base.hsc" #-}
    (190) -> DLT_CAN20B
{-# LINE 1443 "Network/Pcap/Base.hsc" #-}

{-# LINE 1444 "Network/Pcap/Base.hsc" #-}

{-# LINE 1445 "Network/Pcap/Base.hsc" #-}
    (191) -> DLT_IEEE802_15_4_LINUX
{-# LINE 1446 "Network/Pcap/Base.hsc" #-}

{-# LINE 1447 "Network/Pcap/Base.hsc" #-}

{-# LINE 1448 "Network/Pcap/Base.hsc" #-}
    (192) -> DLT_PPI
{-# LINE 1449 "Network/Pcap/Base.hsc" #-}

{-# LINE 1450 "Network/Pcap/Base.hsc" #-}

{-# LINE 1451 "Network/Pcap/Base.hsc" #-}
    (193) -> DLT_IEEE802_16_MAC_CPS_RADIO
{-# LINE 1452 "Network/Pcap/Base.hsc" #-}

{-# LINE 1453 "Network/Pcap/Base.hsc" #-}

{-# LINE 1454 "Network/Pcap/Base.hsc" #-}
    (195) -> DLT_IEEE802_15_4
{-# LINE 1455 "Network/Pcap/Base.hsc" #-}

{-# LINE 1456 "Network/Pcap/Base.hsc" #-}

{-# LINE 1457 "Network/Pcap/Base.hsc" #-}
    unk -> DLT_UNKNOWN (fromIntegral unk)

{-# LINE 1459 "Network/Pcap/Base.hsc" #-}
