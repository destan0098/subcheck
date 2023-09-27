# Check Port 80 and 443 Open Or not And check CDNs
![Static Badge](https://img.shields.io/badge/Go-100%25-brightgreen)
## Description

This Tool Check Subdomains has Open Port 80 or 443 and use cdn or not



- Check http and https
- Show CDN name


## Table of Contents 


- [Installation](#installation)
- [Usage](#usage)


## Installation

```
go install github.com/destan0098/subcheck@latest
```
or use
```
git clone https://github.com/destan0098/subcheck.git

```

## Usage

To Run Enter Below Code
For Use This Enter Website without http  In Input File
Like : https://google.com

```
subcheck -l 'C:\Users\**\Desktop\go2\checksubdomains\input.txt' -o 'C:\Users\***\Desktop\go2\checksubdomains\result4.csv'

```
```
subcheck -d google.com 
```
```
cat inputfile.txt | subcheck -pipe -o output.csv
```




---

## ScreenShot

![IP Show](/screenShot.png?raw=true "Subcheck")


## Features

This Tool Check Subdomains has Open Port 80 or 443 and use cdn or not


