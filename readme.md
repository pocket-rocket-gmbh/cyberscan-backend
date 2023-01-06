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
Backend:
``` bash
npm start
```

Frontend Dev:
``` bash
npm run dev
```

## TODO
* [X] API to start scans
* [X] Start tools in shell
* [X] parse and format result and build json