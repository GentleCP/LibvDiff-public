# Feature Generation
In this document, we illustrate how we generate all features in LibvDiff which includes:
- binary features
- version differences 
- version coordinates

## Binary Features
There are three types of binary features used in LibvDiff:
- basic features: function names (including exports), string literals
- function embeddings
- anchor paths

Two main python scripts are used to generate binary features.
```shell
python feature_generator.py -o freetype  
python feat_encoding.py -o freetype
```

## Version Differences
Before generating version differences, you have to clone the source code of OSS into `data_process/features/OSS-code`. Take freetype as an example,
```shell
git clone https://gitlab.freedesktop.org/freetype/freetype.git data_process/features/freetype/freetype-code
```
Then generate the version differences with `vdcs_generator.py` 
> before running the example, please make sure the source code of OSS and compiled binaries are in the right place. 

```shell
python vdcs_generator.py -o freetype
```

## Version Coordinates
Version coordinates are generated with `vct_generator.py`, you have to generate version differences and basic features at first before generate version coordinates.

```shell
python vct_generator.py -o freetype
```
