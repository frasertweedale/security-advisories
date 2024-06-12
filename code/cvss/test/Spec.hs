{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Text (Text, unpack)
import qualified Security.CVSS as CVSS
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain $
    testGroup "Security.CVSS" $
        map runTest testCases where
            runTest (cvssString, score, rating) = testCase (unpack cvssString) $
                case CVSS.parseCVSS cvssString of
                    Left e -> assertFailure (show e)
                    Right cvss -> do
                        CVSS.cvssScore cvss @?= (rating, score)
                        CVSS.cvssVectorString cvss @?= cvssString
                        CVSS.cvssVectorStringOrdered cvss @?= cvssString

testCases :: [(Text, Float, CVSS.Rating)]
testCases =
    [--("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L", 9.4, CVSS.Critical)
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, CVSS.High)
    , ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8, CVSS.Medium)
    , ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium)
    , ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low)
    , ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, CVSS.Medium)
    , ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium)
    , ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low)
    , ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.0, CVSS.Medium)
    , ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, CVSS.Critical)
    , ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2, CVSS.Medium)
    , ("CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C",          7.8, CVSS.High)
    , ("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",          10,  CVSS.Critical)
    , ("CVSS:2.0/AV:L/AC:H/Au:N/C:C/I:C/A:C",          6.2, CVSS.Medium)
    ]
