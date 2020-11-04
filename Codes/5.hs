-- Recursion
-- Defining the maximum function using recursion to find max element in list
maximum' :: Ord a => [a] -> a
maximum' [] = error "max of empty lists"
maximum' [a] = a
maximum' (a:ab)
        |a > maxTail = a
        | otherwise = maxTail
        where maxTail = maximum' ab

-- Define the replicate functio recursively

replicate' :: (Ord t, Num t) => t -> a -> [a]
replicate' n x
            | n<= 0 = []
            | otherwise = x:replicate' (n-1) x

-- Define take function to get first x elements from a list
take' :: (Ord t, Num t) => t -> [a1] -> [a1]
take' a _
        |a<=0 = []
take' _ [] = []
take' a (b:bc) = b : take' (a-1) bc

-- Define a function to reverse a list using recusrsion
reverse' :: (Ord a, Num a) => [a]->[a]
reverse' [] = []
reverse' (x:xs) =reverse' xs  ++ [x]

-- Define a function to repeat an element to create an infinite list
repeat' :: (Num a) => a -> [a]
repeat' a = a: repeat' a

-- Define a zip function using recurison
zip' :: [a]->[b] -> [(a,b)]
zip' _ [] = []
zip' [] _ = []
zip' (x:xs) (y:ys) = (x,y) : zip' xs ys

-- Define elem using recursion
elem' :: (Num a, Ord a) => [a] -> a -> Bool
elem' [] _ = False
elem' (x:xs) a 
        | a == x = True
        | otherwise = elem' xs a
