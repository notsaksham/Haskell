-- Types and Typeclasses

-- Explicit type declarations

removeNonUpper :: String -> String
removeNonUpper xs = [x|x<-xs , x `elem` ['a'..'z'] || x ==' ']

-- Pattern Matching
-- allows you to write different definiton for different parameteres

lucky :: (Integral a) => a -> String
lucky 7 = "Your input is 7"
lucky x = "Your input is not 7" 

-- Non - recursive definition of factorial
myfact :: (Num a, Enum a) => a -> a
myfact x = product[1..x]

-- Recursive definition of factorial
-- Define fact of 0 is 1 then continue from there
recurfact :: (Integral a)=> a -> a
recurfact 0 = 1
recurfact x = x * recurfact (x-1)

-- Write functions to extract individual elems from a triple, first, second and third
-- use _ in parameteres to not consider it
first :: (a,a,a) -> a
first (a,_,_) = a
second ::(a,a,a) -> a
second (_,b,_) = b
third ::(a,a,a) -> a
third (_,_,c) = c

-- Define a head function using : to retun firts element
head' :: [a]->a
head' [] = error "Can't find the head of an empty list"
head' (x:_) = x 



-- Define a secondary function to return first 2 elements of a list
-- hlint does show an error for the middle 2 conditions but compiles and executes succesfully
secondary ::(Show a) => [a] -> String
secondary [] = "The list is empty"
secondary (x:[]) = "There is only 1 element " ++ show x
secondary (x:y:[]) = "There is only 2 elements "++ show x ++" and "++ show y
secondary (x:y:_) = "The first 2 elements in the list are " ++ show x ++ " and " ++ show y


{-
JUST A TRY TO SEE WHAT THE TEXTBOOK HAS WORKS OR NOT
tell :: ( Show a ) => [ a ] -> String
tell [] = " The list is empty "
tell ( x :[]) = " The list has one element : " ++ show x
tell ( x : y :[]) = " The list has two elements : " ++ show x ++ " and " ++ show y
tell ( x : y : _ ) = " This list is long . The first two elements are : " ++ show x ++" and " ++ show y
-}

-- Using a pattern matching
-- in line 64 show x can be replaced by [x] but can not write just x
usingat :: String -> String
usingat "" = "Empty string"
usingat all@(x:_) =  "The first letter of " ++ all ++ " is " ++ show x

-- Guards are more or less versatile switch statements of Haskell

-- A fucntion using guards to categorize BMI
bmiTell :: (RealFloat a) => a -> String
bmiTell bmi
    | bmi <= 18.5 = "You are underweight ma man"
    | bmi <= 25.0 = "Normie shit"
    | bmi <= 30.0 = "Gotta lose some weight dude"
    | otherwise = "Morbid obesity is not a joke, but you are"

-- A function  using guards to return capitalized vowels if input is a vowel
vowelTell ::  Char -> String
vowelTell cha
    | cha == 'a' = "A"
    | cha == 'e' = "E"
    | cha == 'i' = "I"
    | cha == 'o' = "O"
    | cha == 'u' = "U"
    | otherwise = "Not a vowel DUM DUM"

-- Write a guard function for finding max , and make it an infix definition
-- Ord is a typeclass for anyhting that can be comapred , and Ordering is the type of GT(Greater than) , LT()
myCompare :: (Ord a) => a->a-> Ordering
a `myCompare` b
    | a > b = GT
    | a < b = LT
    | otherwise = EQ

