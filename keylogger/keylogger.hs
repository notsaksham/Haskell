import System.IO
import System.Process
import Control.Monad

infi= do 
        input <- getLine
        writefile <- openFile "example.txt" AppendMode
        hPutStrLn writefile input
        hClose writefile
        