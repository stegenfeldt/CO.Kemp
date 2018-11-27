# CO.Kemp

A System Center Operations Manager management pack for monitoring KEMP Loadmaster nodes and clusters.  
Uses the KEMP REST-API instead of SNMP.

## How to contribute

- Create your own fork to develop against, always use the correct branch/tag as base for your changed (see [branches](#Branches) and [tags](#Tags))
- Create a suitable branch for your changes to work on
- Before starting, make sure you're in sync with the upstream repository
- Write useful commit messages (we need to understand the "what" and "why")
- Maintain the changelog
- Pull from upstream and test merge before creating a pull-request

## Project dependencies

### IDE

The project is developed using **Visual Studio 2015+** with **Visual Studio Authoring Extensions** installed.
Since it is OpenSource, it is compatible, both technically and legally, with Visual Studio Community Edition.

To make development and distribution simpler, we copy any compiled/built `.mp`, `.mpb` and `.xml`-files to the /LatestBuild folder.  
Easiest way to do this is using the *Auto Deploy* extension for Visual Studio. Configure it to copy these files to `../LatestBuild`.

## Branches

### master

This is our "stable" branch. Stuff here is tested and, hopefully, true. 

### develop

Our base for active development. Feature branched are created with `develop` as base and changes will be merged back into `develop` when done. 

### feature/*

All feature-branches should be named `feature/the-feature-i-am-working-on`. If you are working on an issue (not hotfix), please make a feature-branch for it. I.e. `feature/issue-21` or similar.  
These are a great place to test stuff out.

When you consider your feature done, pull develop from upstream, merge into your feature branch, test. If it's working, create a pull-request against our `develop`.

### hotfix/*

Hotfix branches are used when there's a severe issue with the something in the master ("stable") branch. These branches are created from either the latest master or the relevant version tag. When tested and true, create a pull-request against master. We will make sure `develop` is updated as needed.  
Hotfix branches must follow the `hotfix/issue-ISSUENUMBER` convention. 

## Tags

There will be a version-tag created for every "significant" release. 

There will always be the latest and greatest available from the LatestBuild directory in `develop`, if you want to live on the edge. These should be functional as most work is made against feature-branches, but who knows?

When a feature-set is completed or a hotfix implemented, `master` will be updated and a version-tag will be set.
