-- Higher order Functions
-- Any function which takes functions as parameteres or returns functions is a higher order functions

{- 
   Currying Functions
   Functions is haskell can only take in 1 parameter, all multiple parameters passed are actually curried internally
   Curried function is when
   max 4 5 = max (max 4) 5 
-}

-- Write a function that returns a function which compares any digit with 100
comparewithHundred :: Integer -> Ordering
comparewithHundred = compare 100

-- Similar function can be returned for infix operation
divideBy100 :: Double -> Double
divideBy100 = (/100)

-- Similar function to return elem
findElem :: Char -> Bool
findElem = (`elem` ['A'..'Z'])

-- Define a function which takes a function as a parameter
-- This function takes f as a parameter, to call cmd is `applyTwice divideby100 20000`
applyTwice :: (a->a) -> a-> a
applyTwice f x = f (f x)

-- Define a higher oprder zipWith function recursively
-- Function takes in a function which takes a&b as parameteres and returns c as well as lists of type a and b and returns a list of type c
zipWith' :: (a->b->c) -> [a] -> [b] -> [c]
zipWith' _ [] _ = []
zipWith' _ _ [] = []
zipWith' f (x:xs) (y:ys) = f x y : zipWith' f xs ys
-- The above defined function can be used to perform function f on 2 lists while zipping them
-- zipWith' (+) [1,2,3] [4,5,6] = [5,7,9]
-- the last pattern matching statement extracts the head of the array applies f on them and then passes the headless lists to itself until one of the lists are empty and the results are appended

-- Define a function which returns a function with flipped parameteres
flip' :: (a -> b -> c) ->  (b->a -> c)
flip' f = g
        where g x y = f y x
-- Side note : MIND = BLOWN

-- Define the same function as above but no need to return a function
myflip :: (a->b->c) -> b -> a -> c
myflip f x y = f y x
-- In the type declaration take in parameters as a function which takes in type a and b (returning c) and take in the actual parameteres but in order b a ,and return the c as the end result 
-- No function retured here, just the computation was performed on the reversed parameteres

-- MAPS AND FILTERS
{-
    maps is same as javascript map - takes an operation and applies to all elements in a list, alternative for for& while. lol
    :t map = (a->b) -> [a] -> [b]
    clearly versatile af
-}
{-
    filter is a function that takes a predicate and a list and then returns a list of elements that satisfy the predicate
    NOTE: Predicate is a function that returns a bool
    :t filter = (a->bool) -> [a] -> [a]
-}

-- Define a predicate and then pass that predicate to a filter function
mypredicate :: (Ord a, Num a) => a -> Bool
mypredicate a
        | a < 0  = True
        | otherwise = False

myfilterapp :: (a -> Bool) -> [a] -> [a]
myfilterapp mypredicate xs = filter mypredicate xs
-- The above function is useless and can be implemented by ```filter (<0) xs```

-- Implemented quicksort with filters in quicksort.hs, slightly simplifying it by removing the expression process

-- Define a  function within a function using where to find divisible numbers by 3892 from 1-10000
largestDivisible :: (Integral a) => a 
largestDivisible = head (filter p [10000,9999..])
                    where p x = x `mod` 3892 == 0

    


