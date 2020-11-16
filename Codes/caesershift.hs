import Data.Char ()

shiftFwd :: [Char] -> [Char]
shiftFwd = map shiftForwards

shiftForwards :: Char -> Char
shiftForwards 'z' = 'a'
shiftForwards c   = succ c
