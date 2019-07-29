# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.0.0-alpha.3]

### Added

- CO.Kemp.LoadMaster.APIAvailability.Monitor
- CO.Kemp.LoadMaster.HA1IsActive.Collection
- CO.Kemp.LoadMaster.HA2IsActive.Collection

### Changed
- Added variable/module cleanup routines to scripts to minimize memory leakage
- Improved debugging settings, removed unwanted output

### Fixed

- VS Port discovery, now functional and SquaredUp VADA-compatible.

## [v1.0.0-alpha.2]

### Added

- Gathering performance data from API
- CO.Kemp.PerformanceDataMapper.DataSource
- CO.Kemp.VSConnsPerSecCollection (disabled for compatibility, should be removed when possible)
- CO.Kemp.VirtualService.ConnectionsPerSec.Collection
- CO.Kemp.VirtualService.ActiveConnections.Collection
- CO.Kemp.SubVirtualService.ConnectionPerSec.Collection
- CO.Kemp.SubVirtualService.ActiveConnections.Collection
- CO.Kemp.LoadMaster.VSTotals_PktsPerSec.Collection
- CO.Kemp.LoadMaster.CPUSystemTotal.Collection
- CO.Kemp.LoadMaster.MEMUsed.Collection
- CO.Kemp.LoadMaster.MEMUsedPct.Collection
- CO.Kemp.LoadMaster.MEMFree.Collection
- CO.Kemp.LoadMaster.MEMFreePct.Collection
- CO.Kemp.LoadMaster.VSTotals_ConnsPerSec.Collection
- CO.Kemp.LoadMaster.VSTotals_BitsPerSec.Collection
- CO.Kemp.LoadMaster.VSTotals_BytesPerSec.Collection

### Changed

- Updated changelog with [v1.0.0-alpha]

### Fixed

- Issue #10, RS Containment discovery is now connecting the correct RS to VS/SubVS.
- Spellcheck on VS/SubVS displaystrings
- VSAddress on VS/SubVS is now populated
- VS/SubVS Nickname property displaystring

## [v1.0.0-alpha]

### Added

- Changelog
- Classes (LM, VS, SubVS, RS)
- Relationships
- Discovery of LM, VS, SubVS and RS with relationships
- RunAs profile
- Monitoring on VS/SubVS and RS

[Unreleased]: https://github.com/ClasOhlson/CO.Kemp/compare/v1.0.0-alpha.3...HEAD
[v1.0.0-alpha.3]: https://github.com/ClasOhlson/CO.Kemp/compare/v1.0.0-alpha.2...v1.0.0-alpha.3
[v1.0.0-alpha.2]: https://github.com/ClasOhlson/CO.Kemp/compare/v1.0.0-alpha...v1.0.0-alpha.2
[v1.0.0-alpha]: https://github.com/ClasOhlson/CO.Kemp/compare/2363f6e3025e430963c61f8420f05d549ddfe007...v1.0.0-alpha
