{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Security.V4_0.CVSS40Lookup
  ( EQ1(..), EQ2(..), EQ4(..), EQ5(..), EQ3_EQ6(..), MacroVector(..), macroVectorScore
  , lookupScore, maxComposed, maxComposedEQ3, maxSeverityeq3eq6, maxSeverity
  , maxSeverityEQ1, maxSeverityEQ2, maxSeverityEQ3_EQ6, maxSeverityEQ4, maxSeverityEQ5
  , maxComposedEQ1, maxComposedEQ2, maxComposedEQ3_EQ6, maxComposedEQ4, maxComposedEQ5
  ) where

import qualified Data.Map as Map
import Data.Text (Text)

data EQ1 = EQ1_0 | EQ1_1 | EQ1_2

data EQ2 = EQ2_0 | EQ2_1

data EQ4 = EQ4_0 | EQ4_1 | EQ4_2

data EQ5 = EQ5_0 | EQ5_1 | EQ5_2

-- | Joint EQ3+EQ6 - MacroVectors
data EQ3_EQ6
  = EQ3_EQ6_00
  | EQ3_EQ6_01
  | EQ3_EQ6_10
  | EQ3_EQ6_11
  | EQ3_EQ6_21

data MacroVector = MacroVector EQ1 EQ2 EQ4 EQ5 EQ3_EQ6

-- | Return list of "lower" MacroVector values by lowering
-- each of the EQ components.
lowerMacroVectors :: MacroVector -> [MacroVector]
lowerMacroVectors (MacroVector eq1 eq2 eq4 eq5 eq36) =
  fmap (\eq1' -> MacroVector eq1' eq2 eq4 eq5 eq36) lowerEQ1
  ++ fmap (\eq2' -> MacroVector eq1 eq2' eq4 eq5 eq36) lowerEQ2
  ++ fmap (\eq4' -> MacroVector eq1 eq2 eq4' eq5 eq36) lowerEQ4
  ++ fmap (\eq5' -> MacroVector eq1 eq2 eq4 eq5' eq36) lowerEQ5
  ++ fmap (\eq36' -> MacroVector eq1 eq2 eq4 eq5 eq36') lowerEQ36
  where
    lowerEQ1 = case eq1 of EQ1_0 -> [EQ1_1] ; EQ1_1 -> [EQ1_2] ; _ -> []
    lowerEQ2 = case eq2 of EQ2_0 -> [EQ2_1] ; _ -> []
    lowerEQ4 = case eq4 of EQ4_0 -> [EQ4_1] ; EQ4_1 -> [EQ4_2] ; _ -> []
    lowerEQ5 = case eq5 of EQ5_0 -> [EQ5_1] ; EQ5_1 -> [EQ5_2] ; _ -> []
    lowerEQ36 = case eq36 of
      EQ3_EQ6_00 -> [EQ3_EQ6_01, EQ3_EQ6_10]
      EQ3_EQ6_01 -> [EQ3_EQ6_11]
      EQ3_EQ6_10 -> [EQ3_EQ6_11]
      EQ3_EQ6_11 -> [EQ3_EQ6_21]
      EQ3_EQ6_21 -> []

maxSeverityEQ1 :: EQ1 -> Float
maxSeverityEQ1 = \case
  EQ1_0 -> 1
  EQ1_1 -> 4
  EQ1_2 -> 5

maxSeverityEQ2 :: EQ2 -> Float
maxSeverityEQ2 = \case
  EQ2_0 -> 1
  EQ2_1 -> 2

maxSeverityEQ4 :: EQ4 -> Float
maxSeverityEQ4 = \case
  EQ4_0 -> 6
  EQ4_1 -> 5
  EQ4_2 -> 4

maxSeverityEQ5 :: EQ5 -> Float
maxSeverityEQ5 = \case
  EQ5_0 -> 1
  EQ5_1 -> 1
  EQ5_2 -> 1

maxSeverityEQ3_EQ6 :: EQ3_EQ6 -> Float
maxSeverityEQ3_EQ6 = \case
  EQ3_EQ6_00 -> 7
  EQ3_EQ6_01 -> 6
  EQ3_EQ6_10 -> 8
  EQ3_EQ6_11 -> 8
  EQ3_EQ6_21 -> 10

maxComposedEQ1 :: EQ1 -> [Text]
maxComposedEQ1 = \case
  EQ1_0 -> ["AV:N/PR:N/UI:N/"]
  EQ1_1 -> ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"]
  EQ1_2 -> ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]

maxComposedEQ2 :: EQ2 -> [Text]
maxComposedEQ2 = \case
  EQ2_0 -> ["AC:L/AT:N/"]
  EQ2_1 -> ["AC:H/AT:N/", "AC:L/AT:P/"]

maxComposedEQ4 :: EQ4 -> [Text]
maxComposedEQ4 = \case
  EQ4_0 -> ["SC:H/SI:S/SA:S/"]
  EQ4_1 -> ["SC:H/SI:H/SA:H/"]
  EQ4_2 -> ["SC:L/SI:L/SA:L/"]

maxComposedEQ5 :: EQ5 -> [Text]
maxComposedEQ5 = \case
  EQ5_0 -> ["E:A/"]
  EQ5_1 -> ["E:P/"]
  EQ5_2 -> ["E:U/"]

maxComposedEQ3_EQ6 :: EQ3_EQ6 -> [Text]
maxComposedEQ3_EQ6 = \case
  EQ3_EQ6_00 -> ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"]
  EQ3_EQ6_01 -> ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]
  EQ3_EQ6_10 -> ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"]
  EQ3_EQ6_11 -> ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]
  EQ3_EQ6_21 -> ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]


macroVectorScore :: MacroVector -> Float
macroVectorScore v = case v of
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_00 -> 10
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_01 -> 9.9
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_00 -> 9.8
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_01 -> 9.5
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_00 -> 9.5
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_01 -> 9.2
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_00 -> 10
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_01 -> 9.6
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_00 -> 9.3
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_01 -> 8.7
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_00 -> 9.1
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_01 -> 8.1
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_00 -> 9.3
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_01 -> 9
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_00 -> 8.9
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_01 -> 8
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_00 -> 8.1
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_01 -> 6.8
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_10 -> 9.8
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_11 -> 9.5
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_10 -> 9.5
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_11 -> 9.2
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_10 -> 9
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_11 -> 8.4
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_10 -> 9.3
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_11 -> 9.2
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_10 -> 8.9
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_11 -> 8.1
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_10 -> 8.1
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_11 -> 6.5
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_10 -> 8.8
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_11 -> 8
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_10 -> 7.8
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_11 -> 7
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_10 -> 6.9
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_11 -> 4.8
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_21 -> 9.2
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_21 -> 8.2
  MacroVector EQ1_0 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_21 -> 7.2
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_21 -> 7.9
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_21 -> 6.9
  MacroVector EQ1_0 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_21 -> 5
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_21 -> 6.9
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_21 -> 5.5
  MacroVector EQ1_0 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_21 -> 2.7
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_00 -> 9.9
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_01 -> 9.7
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_00 -> 9.5
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_01 -> 9.2
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_00 -> 9.2
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_01 -> 8.5
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_00 -> 9.5
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_01 -> 9.1
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_00 -> 9
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_01 -> 8.3
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_00 -> 8.4
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_01 -> 7.1
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_00 -> 9.2
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_01 -> 8.1
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_00 -> 8.2
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_01 -> 7.1
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_00 -> 7.2
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_01 -> 5.3
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_10 -> 9.5
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_11 -> 9.3
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_10 -> 9.2
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_11 -> 8.5
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_10 -> 8.5
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_11 -> 7.3
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_10 -> 9.2
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_11 -> 8.2
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_10 -> 8
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_11 -> 7.2
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_10 -> 7
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_11 -> 5.9
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_10 -> 8.4
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_11 -> 7
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_10 -> 7.1
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_11 -> 5.2
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_10 -> 5
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_11 -> 3
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_21 -> 8.6
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_21 -> 7.5
  MacroVector EQ1_0 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_21 -> 5.2
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_21 -> 7.1
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_21 -> 5.2
  MacroVector EQ1_0 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_21 -> 2.9
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_21 -> 6.3
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_21 -> 2.9
  MacroVector EQ1_0 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_21 -> 1.7
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_00 -> 9.8
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_01 -> 9.5
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_00 -> 9.4
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_01 -> 8.7
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_00 -> 9.1
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_01 -> 8.1
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_00 -> 9.4
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_01 -> 8.9
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_00 -> 8.6
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_01 -> 7.4
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_00 -> 7.7
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_01 -> 6.4
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_00 -> 8.7
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_01 -> 7.5
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_00 -> 7.4
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_01 -> 6.3
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_00 -> 6.3
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_01 -> 4.9
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_10 -> 9.4
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_11 -> 8.9
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_10 -> 8.8
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_11 -> 7.7
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_10 -> 7.6
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_11 -> 6.7
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_10 -> 8.6
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_11 -> 7.6
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_10 -> 7.4
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_11 -> 5.8
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_10 -> 5.9
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_11 -> 5
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_10 -> 7.2
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_11 -> 5.7
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_10 -> 5.7
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_11 -> 5.2
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_10 -> 5.2
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_11 -> 2.5
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_21 -> 8.3
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_21 -> 7
  MacroVector EQ1_1 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_21 -> 5.4
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_21 -> 6.5
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_21 -> 5.8
  MacroVector EQ1_1 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_21 -> 2.6
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_21 -> 5.3
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_21 -> 2.1
  MacroVector EQ1_1 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_21 -> 1.3
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_00 -> 9.5
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_01 -> 9
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_00 -> 8.8
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_01 -> 7.6
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_00 -> 7.6
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_01 -> 7
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_00 -> 9
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_01 -> 7.7
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_00 -> 7.5
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_01 -> 6.2
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_00 -> 6.1
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_01 -> 5.3
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_00 -> 7.7
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_01 -> 6.6
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_00 -> 6.8
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_01 -> 5.9
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_00 -> 5.2
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_01 -> 3
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_10 -> 8.9
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_11 -> 7.8
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_10 -> 7.6
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_11 -> 6.7
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_10 -> 6.2
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_11 -> 5.8
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_10 -> 7.4
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_11 -> 5.9
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_10 -> 5.7
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_11 -> 5.7
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_10 -> 4.7
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_11 -> 2.3
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_10 -> 6.1
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_11 -> 5.2
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_10 -> 5.7
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_11 -> 2.9
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_10 -> 2.4
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_11 -> 1.6
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_21 -> 7.1
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_21 -> 5.9
  MacroVector EQ1_1 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_21 -> 3
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_21 -> 5.8
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_21 -> 2.6
  MacroVector EQ1_1 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_21 -> 1.5
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_21 -> 2.3
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_21 -> 1.3
  MacroVector EQ1_1 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_21 -> 0.6
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_00 -> 9.3
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_01 -> 8.7
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_00 -> 8.6
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_01 -> 7.2
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_00 -> 7.5
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_01 -> 5.8
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_00 -> 8.6
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_01 -> 7.4
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_00 -> 7.4
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_01 -> 6.1
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_00 -> 5.6
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_01 -> 3.4
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_00 -> 7
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_01 -> 5.4
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_00 -> 5.2
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_01 -> 4
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_00 -> 4
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_01 -> 2.2
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_10 -> 8.5
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_11 -> 7.5
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_10 -> 7.4
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_11 -> 5.5
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_10 -> 6.2
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_11 -> 5.1
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_10 -> 7.2
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_11 -> 5.7
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_10 -> 5.5
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_11 -> 4.1
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_10 -> 4.6
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_11 -> 1.9
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_10 -> 5.3
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_11 -> 3.6
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_10 -> 3.4
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_11 -> 1.9
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_10 -> 1.9
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_11 -> 0.8
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_0 EQ3_EQ6_21 -> 6.4
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_1 EQ3_EQ6_21 -> 5.1
  MacroVector EQ1_2 EQ2_0 EQ4_0 EQ5_2 EQ3_EQ6_21 -> 2
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_0 EQ3_EQ6_21 -> 4.7
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_1 EQ3_EQ6_21 -> 2.1
  MacroVector EQ1_2 EQ2_0 EQ4_1 EQ5_2 EQ3_EQ6_21 -> 1.1
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_0 EQ3_EQ6_21 -> 2.4
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_1 EQ3_EQ6_21 -> 0.9
  MacroVector EQ1_2 EQ2_0 EQ4_2 EQ5_2 EQ3_EQ6_21 -> 0.4
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_00 -> 8.8
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_01 -> 7.5
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_00 -> 7.3
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_01 -> 5.3
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_00 -> 6
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_01 -> 5
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_00 -> 7.3
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_01 -> 5.5
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_00 -> 5.9
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_01 -> 4
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_00 -> 4.1
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_01 -> 2
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_00 -> 5.4
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_01 -> 4.3
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_00 -> 4.5
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_01 -> 2.2
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_00 -> 2
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_01 -> 1.1
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_10 -> 7.5
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_11 -> 5.5
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_10 -> 5.8
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_11 -> 4.5
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_10 -> 4
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_11 -> 2.1
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_10 -> 6.1
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_11 -> 5.1
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_10 -> 4.8
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_11 -> 1.8
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_10 -> 2
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_11 -> 0.9
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_10 -> 4.6
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_11 -> 1.8
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_10 -> 1.7
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_11 -> 0.7
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_10 -> 0.8
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_11 -> 0.2
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_0 EQ3_EQ6_21 -> 5.3
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_1 EQ3_EQ6_21 -> 2.4
  MacroVector EQ1_2 EQ2_1 EQ4_0 EQ5_2 EQ3_EQ6_21 -> 1.4
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_0 EQ3_EQ6_21 -> 2.4
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_1 EQ3_EQ6_21 -> 1.2
  MacroVector EQ1_2 EQ2_1 EQ4_1 EQ5_2 EQ3_EQ6_21 -> 0.5
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_0 EQ3_EQ6_21 -> 1
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_1 EQ3_EQ6_21 -> 0.3
  MacroVector EQ1_2 EQ2_1 EQ4_2 EQ5_2 EQ3_EQ6_21 -> 0.1

lookupScore :: Map.Map [Int] Float
lookupScore = Map.fromList
  [  ([1,0,0,0,0,0], 9.8)
    ,([1,0,0,0,0,1], 9.5)
    ,([1,0,0,0,1,0], 9.4)
    ,([1,0,0,0,1,1], 8.7)
    ,([1,0,0,0,2,0], 9.1)
    ,([1,0,0,0,2,1], 8.1)
    ,([1,0,0,1,0,0], 9.4)
    ,([1,0,0,1,0,1], 8.9)
    ,([1,0,0,1,1,0], 8.6)
    ,([1,0,0,1,1,1], 7.4)
    ,([1,0,0,1,2,0], 7.7)
    ,([1,0,0,1,2,1], 6.4)
    ,([1,0,0,2,0,0], 8.7)
    ,([1,0,0,2,0,1], 7.5)
    ,([1,0,0,2,1,0], 7.4)
    ,([1,0,0,2,1,1], 6.3)
    ,([1,0,0,2,2,0], 6.3)
    ,([1,0,0,2,2,1], 4.9)
    ,([1,0,1,0,0,0], 9.4)
    ,([1,0,1,0,0,1], 8.9)
    ,([1,0,1,0,1,0], 8.8)
    ,([1,0,1,0,1,1], 7.7)
    ,([1,0,1,0,2,0], 7.6)
    ,([1,0,1,0,2,1], 6.7)
    ,([1,0,1,1,0,0], 8.6)
    ,([1,0,1,1,0,1], 7.6)
    ,([1,0,1,1,1,0], 7.4)
    ,([1,0,1,1,1,1], 5.8)
    ,([1,0,1,1,2,0], 5.9)
    ,([1,0,1,1,2,1], 5)
    ,([1,0,1,2,0,0], 7.2)
    ,([1,0,1,2,0,1], 5.7)
    ,([1,0,1,2,1,0], 5.7)
    ,([1,0,1,2,1,1], 5.2)
    ,([1,0,1,2,2,0], 5.2)
    ,([1,0,1,2,2,1], 2.5)
    ,([1,0,2,0,0,1], 8.3)
    ,([1,0,2,0,1,1], 7)
    ,([1,0,2,0,2,1], 5.4)
    ,([1,0,2,1,0,1], 6.5)
    ,([1,0,2,1,1,1], 5.8)
    ,([1,0,2,1,2,1], 2.6)
    ,([1,0,2,2,0,1], 5.3)
    ,([1,0,2,2,1,1], 2.1)
    ,([1,0,2,2,2,1], 1.3)
    ,([1,1,0,0,0,0], 9.5)
    ,([1,1,0,0,0,1], 9)
    ,([1,1,0,0,1,0], 8.8)
    ,([1,1,0,0,1,1], 7.6)
    ,([1,1,0,0,2,0], 7.6)
    ,([1,1,0,0,2,1], 7)
    ,([1,1,0,1,0,0], 9)
    ,([1,1,0,1,0,1], 7.7)
    ,([1,1,0,1,1,0], 7.5)
    ,([1,1,0,1,1,1], 6.2)
    ,([1,1,0,1,2,0], 6.1)
    ,([1,1,0,1,2,1], 5.3)
    ,([1,1,0,2,0,0], 7.7)
    ,([1,1,0,2,0,1], 6.6)
    ,([1,1,0,2,1,0], 6.8)
    ,([1,1,0,2,1,1], 5.9)
    ,([1,1,0,2,2,0], 5.2)
    ,([1,1,0,2,2,1], 3)
    ,([1,1,1,0,0,0], 8.9)
    ,([1,1,1,0,0,1], 7.8)
    ,([1,1,1,0,1,0], 7.6)
    ,([1,1,1,0,1,1], 6.7)
    ,([1,1,1,0,2,0], 6.2)
    ,([1,1,1,0,2,1], 5.8)
    ,([1,1,1,1,0,0], 7.4)
    ,([1,1,1,1,0,1], 5.9)
    ,([1,1,1,1,1,0], 5.7)
    ,([1,1,1,1,1,1], 5.7)
    ,([1,1,1,1,2,0], 4.7)
    ,([1,1,1,1,2,1], 2.3)
    ,([1,1,1,2,0,0], 6.1)
    ,([1,1,1,2,0,1], 5.2)
    ,([1,1,1,2,1,0], 5.7)
    ,([1,1,1,2,1,1], 2.9)
    ,([1,1,1,2,2,0], 2.4)
    ,([1,1,1,2,2,1], 1.6)
    ,([1,1,2,0,0,1], 7.1)
    ,([1,1,2,0,1,1], 5.9)
    ,([1,1,2,0,2,1], 3)
    ,([1,1,2,1,0,1], 5.8)
    ,([1,1,2,1,1,1], 2.6)
    ,([1,1,2,1,2,1], 1.5)
    ,([1,1,2,2,0,1], 2.3)
    ,([1,1,2,2,1,1], 1.3)
    ,([1,1,2,2,2,1], 0.6)
    ,([2,0,0,0,0,0], 9.3)
    ,([2,0,0,0,0,1], 8.7)
    ,([2,0,0,0,1,0], 8.6)
    ,([2,0,0,0,1,1], 7.2)
    ,([2,0,0,0,2,0], 7.5)
    ,([2,0,0,0,2,1], 5.8)
    ,([2,0,0,1,0,0], 8.6)
    ,([2,0,0,1,0,1], 7.4)
    ,([2,0,0,1,1,0], 7.4)
    ,([2,0,0,1,1,1], 6.1)
    ,([2,0,0,1,2,0], 5.6)
    ,([2,0,0,1,2,1], 3.4)
    ,([2,0,0,2,0,0], 7)
    ,([2,0,0,2,0,1], 5.4)
    ,([2,0,0,2,1,0], 5.2)
    ,([2,0,0,2,1,1], 4)
    ,([2,0,0,2,2,0], 4)
    ,([2,0,0,2,2,1], 2.2)
    ,([2,0,1,0,0,0], 8.5)
    ,([2,0,1,0,0,1], 7.5)
    ,([2,0,1,0,1,0], 7.4)
    ,([2,0,1,0,1,1], 5.5)
    ,([2,0,1,0,2,0], 6.2)
    ,([2,0,1,0,2,1], 5.1)
    ,([2,0,1,1,0,0], 7.2)
    ,([2,0,1,1,0,1], 5.7)
    ,([2,0,1,1,1,0], 5.5)
    ,([2,0,1,1,1,1], 4.1)
    ,([2,0,1,1,2,0], 4.6)
    ,([2,0,1,1,2,1], 1.9)
    ,([2,0,1,2,0,0], 5.3)
    ,([2,0,1,2,0,1], 3.6)
    ,([2,0,1,2,1,0], 3.4)
    ,([2,0,1,2,1,1], 1.9)
    ,([2,0,1,2,2,0], 1.9)
    ,([2,0,1,2,2,1], 0.8)
    ,([2,0,2,0,0,1], 6.4)
    ,([2,0,2,0,1,1], 5.1)
    ,([2,0,2,0,2,1], 2)
    ,([2,0,2,1,0,1], 4.7)
    ,([2,0,2,1,1,1], 2.1)
    ,([2,0,2,1,2,1], 1.1)
    ,([2,0,2,2,0,1], 2.4)
    ,([2,0,2,2,1,1], 0.9)
    ,([2,0,2,2,2,1], 0.4)
    ,([2,1,0,0,0,0], 8.8)
    ,([2,1,0,0,0,1], 7.5)
    ,([2,1,0,0,1,0], 7.3)
    ,([2,1,0,0,1,1], 5.3)
    ,([2,1,0,0,2,0], 6)
    ,([2,1,0,0,2,1], 5)
    ,([2,1,0,1,0,0], 7.3)
    ,([2,1,0,1,0,1], 5.5)
    ,([2,1,0,1,1,0], 5.9)
    ,([2,1,0,1,1,1], 4)
    ,([2,1,0,1,2,0], 4.1)
    ,([2,1,0,1,2,1], 2)
    ,([2,1,0,2,0,0], 5.4)
    ,([2,1,0,2,0,1], 4.3)
    ,([2,1,0,2,1,0], 4.5)
    ,([2,1,0,2,1,1], 2.2)
    ,([2,1,0,2,2,0], 2)
    ,([2,1,0,2,2,1], 1.1)
    ,([2,1,1,0,0,0], 7.5)
    ,([2,1,1,0,0,1], 5.5)
    ,([2,1,1,0,1,0], 5.8)
    ,([2,1,1,0,1,1], 4.5)
    ,([2,1,1,0,2,0], 4)
    ,([2,1,1,0,2,1], 2.1)
    ,([2,1,1,1,0,0], 6.1)
    ,([2,1,1,1,0,1], 5.1)
    ,([2,1,1,1,1,0], 4.8)
    ,([2,1,1,1,1,1], 1.8)
    ,([2,1,1,1,2,0], 2)
    ,([2,1,1,1,2,1], 0.9)
    ,([2,1,1,2,0,0], 4.6)
    ,([2,1,1,2,0,1], 1.8)
    ,([2,1,1,2,1,0], 1.7)
    ,([2,1,1,2,1,1], 0.7)
    ,([2,1,1,2,2,0], 0.8)
    ,([2,1,1,2,2,1], 0.2)
    ,([2,1,2,0,0,1], 5.3)
    ,([2,1,2,0,1,1], 2.4)
    ,([2,1,2,0,2,1], 1.4)
    ,([2,1,2,1,0,1], 2.4)
    ,([2,1,2,1,1,1], 1.2)
    ,([2,1,2,1,2,1], 0.5)
    ,([2,1,2,2,0,1], 1)
    ,([2,1,2,2,1,1], 0.3)
    ,([2,1,2,2,2,1], 0.1)
    ,([0,0,0,0,0,0], 10)
    ,([0,0,0,0,0,1], 9.9)
    ,([0,0,0,0,1,0], 9.8)
    ,([0,0,0,0,1,1], 9.5)
    ,([0,0,0,0,2,0], 9.5)
    ,([0,0,0,0,2,1], 9.2)
    ,([0,0,0,1,0,0], 10)
    ,([0,0,0,1,0,1], 9.6)
    ,([0,0,0,1,1,0], 9.3)
    ,([0,0,0,1,1,1], 8.7)
    ,([0,0,0,1,2,0], 9.1)
    ,([0,0,0,1,2,1], 8.1)
    ,([0,0,0,2,0,0], 9.3)
    ,([0,0,0,2,0,1], 9)
    ,([0,0,0,2,1,0], 8.9)
    ,([0,0,0,2,1,1], 8)
    ,([0,0,0,2,2,0], 8.1)
    ,([0,0,0,2,2,1], 6.8)
    ,([0,0,1,0,0,0], 9.8)
    ,([0,0,1,0,0,1], 9.5)
    ,([0,0,1,0,1,0], 9.5)
    ,([0,0,1,0,1,1], 9.2)
    ,([0,0,1,0,2,0], 9)
    ,([0,0,1,0,2,1], 8.4)
    ,([0,0,1,1,0,0], 9.3)
    ,([0,0,1,1,0,1], 9.2)
    ,([0,0,1,1,1,0], 8.9)
    ,([0,0,1,1,1,1], 8.1)
    ,([0,0,1,1,2,0], 8.1)
    ,([0,0,1,1,2,1], 6.5)
    ,([0,0,1,2,0,0], 8.8)
    ,([0,0,1,2,0,1], 8)
    ,([0,0,1,2,1,0], 7.8)
    ,([0,0,1,2,1,1], 7)
    ,([0,0,1,2,2,0], 6.9)
    ,([0,0,1,2,2,1], 4.8)
    ,([0,0,2,0,0,1], 9.2)
    ,([0,0,2,0,1,1], 8.2)
    ,([0,0,2,0,2,1], 7.2)
    ,([0,0,2,1,0,1], 7.9)
    ,([0,0,2,1,1,1], 6.9)
    ,([0,0,2,1,2,1], 5)
    ,([0,0,2,2,0,1], 6.9)
    ,([0,0,2,2,1,1], 5.5)
    ,([0,0,2,2,2,1], 2.7)
    ,([0,1,0,0,0,0], 9.9)
    ,([0,1,0,0,0,1], 9.7)
    ,([0,1,0,0,1,0], 9.5)
    ,([0,1,0,0,1,1], 9.2)
    ,([0,1,0,0,2,0], 9.2)
    ,([0,1,0,0,2,1], 8.5)
    ,([0,1,0,1,0,0], 9.5)
    ,([0,1,0,1,0,1], 9.1)
    ,([0,1,0,1,1,0], 9)
    ,([0,1,0,1,1,1], 8.3)
    ,([0,1,0,1,2,0], 8.4)
    ,([0,1,0,1,2,1], 7.1)
    ,([0,1,0,2,0,0], 9.2)
    ,([0,1,0,2,0,1], 8.1)
    ,([0,1,0,2,1,0], 8.2)
    ,([0,1,0,2,1,1], 7.1)
    ,([0,1,0,2,2,0], 7.2)
    ,([0,1,0,2,2,1], 5.3)
    ,([0,1,1,0,0,0], 9.5)
    ,([0,1,1,0,0,1], 9.3)
    ,([0,1,1,0,1,0], 9.2)
    ,([0,1,1,0,1,1], 8.5)
    ,([0,1,1,0,2,0], 8.5)
    ,([0,1,1,0,2,1], 7.3)
    ,([0,1,1,1,0,0], 9.2)
    ,([0,1,1,1,0,1], 8.2)
    ,([0,1,1,1,1,0], 8)
    ,([0,1,1,1,1,1], 7.2)
    ,([0,1,1,1,2,0], 7)
    ,([0,1,1,1,2,1], 5.9)
    ,([0,1,1,2,0,0], 8.4)
    ,([0,1,1,2,0,1], 7)
    ,([0,1,1,2,1,0], 7.1)
    ,([0,1,1,2,1,1], 5.2)
    ,([0,1,1,2,2,0], 5)
    ,([0,1,1,2,2,1], 3)
    ,([0,1,2,0,0,1], 8.6)
    ,([0,1,2,0,1,1], 7.5)
    ,([0,1,2,0,2,1], 5.2)
    ,([0,1,2,1,0,1], 7.1)
    ,([0,1,2,1,1,1], 5.2)
    ,([0,1,2,1,2,1], 2.9)
    ,([0,1,2,2,0,1], 6.3)
    ,([0,1,2,2,1,1], 2.9)
    ,([0,1,2,2,2,1], 1.7)
  ]

maxComposed :: [[[Text]]]
maxComposed = [
        [
                 ["AV:N/PR:N/UI:N/"],
                 ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
                 ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
        ],
        [
                 ["AC:L/AT:N/"],
                 ["AC:H/AT:N/", "AC:L/AT:P/"]
        ],
        [],-- EQ3+EQ6

        [
                ["SC:H/SI:S/SA:S/"],
                ["SC:H/SI:H/SA:H/"],
                ["SC:L/SI:L/SA:L/"]

        ],
        [
                ["E:A/"],
                ["E:P/"],
                ["E:U/"]
        ]]

maxComposedEQ3 :: [[[Text]]]
maxComposedEQ3 = [
        [ ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"] ],
        [ ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"], ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"] ],
        [ [], ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"] ]]

maxSeverityeq3eq6 :: [[Float]]
maxSeverityeq3eq6 = [
        [ 7, 6 ],
        [ 8, 8 ],
        [ 0, 10 ]]

maxSeverity :: [[Float]]
maxSeverity = [
        [ 1, 4, 5 ],
        [ 1, 2 ],
        [],
        [ 6, 5, 4 ],
        [ 1, 1, 1 ]]
