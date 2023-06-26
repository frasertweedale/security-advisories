{-# LANGUAGE DerivingVia #-}

module Security.Advisories.Definition
  ( Advisory(..)
    -- * Supporting types
  , CWE(..)
  , Architecture(..)
  , AffectedVersionRange(..)
  , OS(..)
  , Keyword(..)
  )
  where

import Data.Text (Text)
import Data.Time (ZonedTime)
import Distribution.Types.ComponentName (ComponentName)
import Distribution.Types.PackageName (PackageName)
import Distribution.Types.VersionRange (VersionRange)

import Text.Pandoc.Definition (Pandoc)

import Security.OSV (Reference)

data Advisory = Advisory
  { advisoryId :: Text
  , advisoryModified :: ZonedTime
  , advisoryPublished :: ZonedTime
  , advisoryPackage :: Text
  , advisoryCWEs :: [CWE]
  , advisoryKeywords :: [Keyword]
  , advisoryAliases :: [Text]
  , advisoryCVSS :: Text
  , advisoryVersions :: [AffectedVersionRange]
  , advisoryArchitectures :: Maybe [Architecture]
  , advisoryOS :: Maybe [OS]
  , advisoryNames :: [(Text, VersionRange)]
  , advisoryReferences :: [Reference]
  , advisoryPandoc :: Pandoc  -- ^ Parsed document, without TOML front matter
  , advisoryHtml :: Text
  , advisorySummary :: Text
    -- ^ A one-line, English textual summary of the vulnerability
  , advisoryDetails :: Text
    -- ^ Details of the vulnerability (CommonMark), without TOML front matter
  }
  deriving stock (Show)

newtype CWE = CWE {unCWE :: Integer}
  deriving stock (Show)

data Architecture
  = AArch64
  | Alpha
  | Arm
  | HPPA
  | HPPA1_1
  | I386
  | IA64
  | M68K
  | MIPS
  | MIPSEB
  | MIPSEL
  | NIOS2
  | PowerPC
  | PowerPC64
  | PowerPC64LE
  | RISCV32
  | RISCV64
  | RS6000
  | S390
  | S390X
  | SH4
  | SPARC
  | SPARC64
  | VAX
  | X86_64
  deriving stock (Show)

data OS
  = Windows
  | MacOS
  | Linux
  | FreeBSD
  | Android
  | NetBSD
  | OpenBSD
  deriving stock (Show)

newtype Keyword = Keyword Text
  deriving stock (Eq, Ord)
  deriving (Show) via Text

data AffectedVersionRange = AffectedVersionRange
  { affectedVersionRangeIntroduced :: Text,
    affectedVersionRangeFixed :: Maybe Text
  }
  deriving stock (Show)

-- @Package@ represents packages or components of the ecosystems
-- monitored by the HSEC database.
--
-- The string representations are:
--
-- @
-- package = [ "[" ecosystem "]" ] package-spec ; default ecosystem = "Hackage"
-- ecosystem = "Hackage" / "GHC"
-- package-spec = name [ ":" component ]  ; component not used for GHC
-- component = "lib" [ ":" name ] \
--             "exe:" name \
--             "flib:" name \
--             "test:" name \
--             "bench:" name
-- @
--
data Package
  = HackagePackage PackageName (Maybe ComponentName)
  -- ^ A ordinary Haskell package.  Absence of 'ComponentName' means
  -- all @lib@ and @exe@ components.  It is possible to represent
  -- @test@ and @bench@ components, though it would be unusual to
  -- publish an advisory for such components.
  | GHCPackage Text
  -- ^ A component of the /Glasgow Haskell Compiler/ ecosystem, e.g.
  -- @compiler@, @GHCi@, @RTS@
  deriving (Show, Eq)
