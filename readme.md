## Cyberscan-Backend
This is the API for the Cyberscan. It manages the user database and the 
running scans.

## Install
You need cyberscan-frontend to run this!

* cyberscan-backend -> API and database
* cyberscan-frontend -> UI and fancy stuff

``` bash
npm install
cp ../cyberscan-frontend/public/* ./public/
```

## Running
``` bash
npm start
```

## TODO
* [ ] API to start scans
* [ ] Start tools in shell
* [ ] parse and format result as json