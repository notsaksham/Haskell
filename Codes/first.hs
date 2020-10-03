
doubleMe x = x+x


doubleUs x y = x*2 +y*2


doubleIfOdd x = if mod x 2 == 1
                    then x *2
                else
                    x
makePairs ls1 ls2 = if length ls1 == length ls2
                        then zip ls1 ls2
                    else
                        zip ls2 ls1

checkOccourence x  = x `elem` [1..100]


mylength' a = sum[1| x<-a]



lowercase' xs = [a| a<-xs, a `elem` ['a'..'z']]

                        
makeTriangle xs= [(a,b,c)|a<-xs,b<-[1..a],c<-[1..b], c ^2 + b ^2 == a ^2 ]

myMakeTriangle =  [ (a ,b , c ) | c <- [1..10] , b <- [1.. c ] , a <-[1.. b ] , a ^2 + b ^2 == c ^2 , a + b + c == 24]
