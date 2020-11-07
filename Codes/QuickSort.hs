-- Implementing quick sort in Haskell
quickSort :: (Ord a) => [a] -> [a]
quickSort [] = []
quickSort (x:xs) = 
            let smallerSorted = quickSort [a | a <- xs , a<=x]
                biggerSorted = quickSort [a | a<-xs, a>x]
            in smallerSorted ++ [x] ++ biggerSorted

{- 
    Quick Explanation
    [3,4,2,1,5]
    takes x = 3 and  xs = [4,2,1,5], 
    smallerSorted is all elements < = 3, meaning smallerSorted = [2,1]
    biggerSorted is all elements > 3 meaninf biggerSorted = [4,5]
    so finally it equals [2,1] ++ [3] ++ [4,5]
    then same is applied to smallerSorted and biggerSorted as well
    in the ned it will return
    [1]++[2]++[]++[3] ++ [] ++ [4] ++ [5] = [1,2,3,4,5]
-}

-- Implementing the same function using Filters from chapter 6
quicksort' :: (Ord a)=>[a] -> [a]
quicksort' [] = []
quicksort' (x:xs) = 
                let smallerSorted = quicksort' (filter (<=x) xs)
                    biggerSorted = quicksort' (filter (>x) xs)
                in smallerSorted ++ [x] ++ biggerSorted