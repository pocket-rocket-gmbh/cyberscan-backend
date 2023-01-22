import fs from 'fs'
import csv from 'csv-parser'
import scanner from './scanner.js';

export class Controller {
    constructor() {
        this.scans = [];
        this.readDB();
        process.on("SIGINT", (signal) => {
            console.log(`\nProcess ${process.pid} has been interrupted`);
            this.cleanScanStatus();
            process.exit(0);
        });
    }
    startTasks(hostname, inputCommand) {
        hostname = hostname.split('.').slice(-2).join('.')
        let task = null
        let taskIndex = this.findTaskIndex(hostname)
        if (taskIndex) {
            task = this.scans[taskIndex]
        }

        switch (inputCommand) {
            case "start":
                // no task found start scanner
                if (!task) {
                    let scan = new scanner.Scan(hostname)
                    this.scans.push(scan)
                }

                // scan is running do nothing
                if (task && task.status == "running") {
                    console.log(`Scan for ${task.hostname} has already started...`)
                }

                // scan was aborted -> rescan
                if (task && (task.status == "aborted" || task.status == "created")) {
                    this.scans[taskIndex] = new scanner.Scan(hostname)
                }

                break;
            default:
                break;
        }
        // save to disk
        this.saveDB();
        return '{status: "Done"}';
    }
    async getReport(hostname) {
        hostname = hostname.split('.').slice(-2).join('.')
        let thisScan = this.findTask(hostname)

        let subs_array = this.readOutputTextFile(hostname, 'subfinder.txt')
        let hosts_array = this.readOutputTextFile(hostname, 'hosts.txt')
        let panels_array = this.readOutputTextFile(hostname, 'panels.txt')
        let webservers_array = this.readOutputTextFile(hostname, 'active_websites.txt')
        let techs_array = this.readOutputTextFile(hostname, 'techs.txt')
        let high_array = this.readOutputTextFile(hostname, 'high.txt')
        let cves_array = this.readOutputTextFile(hostname, 'cve.txt')
        let sqlmap_array = []

        // read all sqlmap results from sqlmap folder
        // TODO -> function
        try {
            let file_list = fs.readdirSync(`./scans/${hostname}/sqlmap/`)
            for (let filename of file_list) {
                if (filename.endsWith(".csv")) {
                    let parsed_csv = await this.parseCSV(`./scans/${hostname}/sqlmap/${filename}`)
                    sqlmap_array.push(parsed_csv)
                }
            }
        } catch (e) {
            // ignore
        }

        // build objects
        let subs = subs_array.filter(e => e)
        let hosts = hosts_array.filter(e => e)
        let panels = panels_array.filter(e => e)
        let webservers = webservers_array.filter(e => e)
        let techs = techs_array.filter(e => e)
        let high = high_array.filter(e => e)
        let cves = cves_array.filter(e => e)
        let sqlmap = sqlmap_array.filter(e => e)

        // group infos by host
        let structured = []
        for (let host of hosts) {
            let hostObject = {}
            hostObject.host = host
            hostObject.webservers = []
            hostObject.panels = []
            hostObject.techs = []
            hostObject.alerts = []

            // filter output lines that dont match the hostname
            hostObject.linesWebservers = this.filterByHost(host, webservers)
            hostObject.linesTechs = this.filterByHost(host, techs)
            hostObject.linesCves = this.filterByHost(host, cves)
            hostObject.linesPanels = this.filterByHost(host, panels)

            // show used technology
            hostObject.techs = hostObject.linesTechs.map(line => {
                return {
                    name: this.getInfoFromIndex(line, 1),
                    info: this.getInfoFromIndex(line, 4)
                }
            })

            // webserver infos
            // eg:  https://api-test.pocket-rocket.io [404] [title] [Cowboy] [AS16509, AS16509, Unknown] [54.73.26.109]
            // index:                                   0        1      2       3                              4
            hostObject.webservers = hostObject.linesWebservers.map(line => {
                return {
                    name: this.getURLfromString(line),
                    title: this.getInfoFromIndex(line, 1),
                    server: this.getInfoFromIndex(line, 2),
                    statusCodes: this.getInfoFromIndex(line, 0),
                    network: this.getInfoFromIndex(line, 3),
                    ip: this.getInfoFromIndex(line, 4),
                    url: this.getURLfromString(line)
                }
            })

            // panel infos
            // eg: [2023-01-03 11:43:31] [drupal-login] [http] [info] https://sub.domain.de
            // index: 0                     1               2   3       4
            hostObject.panels = hostObject.linesPanels.map(line => {
                return {
                    name: this.getInfoFromIndex(line, 1),
                    url: this.getURLfromString(line)
                }
            })

            // tech infos
            // eg: [2023-01-06 09:10:43] [tech-detect:google-font-api] [http] [info] https://domain.de  [nginx/1.6.0]
            // index: 0                         1                       2       3                           4
            hostObject.techs = hostObject.linesTechs.map(line => {
                return {
                    name: this.getInfoFromIndex(line, 1),
                    url: this.getURLfromString(line),
                    value: this.getInfoFromIndex(line, 4)
                }
            })

            // build alerts with sqlmap results
            hostObject.alerts = hostObject.alerts.concat(
                sqlmap.map(alerts => {
                    for (let alert of alerts) {
                        if (alert["Target URL"].indexOf(host) >= 0) {
                            return {
                                title: "SQL Injection",
                                url: alert["Target URL"],
                                severity: "high",
                                description: `Parameter: ${alert['Parameter']}`,
                                cve: null,
                                detection: "SQLmap"
                            }
                        }
                    }
                })
            )

            // add regular cves to alert list
            hostObject.alerts = hostObject.alerts.concat(
                hostObject.linesCves.map(line => {
                    return {
                        title: this.getInfoFromIndex(line, 1),
                        url: this.getURLfromString(line),
                        severity: this.getInfoFromIndex(line, 3),
                        description: this.getInfoFromIndex(line, 4),
                        cve: this.checkIfStringIsCVE(this.getInfoFromIndex(line, 1)),
                        detection: "Nuclei"
                    }
                })
            )

            // filter empty alerts and detections we already have
            hostObject.alerts = hostObject.alerts.filter(e => e)
            // ignore this warning because sqlmap should find this
            hostObject.alerts = hostObject.alerts.filter(e => e.detection != "error-based-sql-injection:MySQL")

            structured.push(hostObject)
        }

        // combine json
        const result = {
            countSubs: subs.length,
            countHosts: hosts.length,
            countWebservers: webservers.length,
            countCVEs: cves.length,
            countHighCVEs: high.length,
            structured: structured,
            status: thisScan.status
        }
        return result;
    }
    findTask(hostname) {
        let scan = this.scans.find(scan => scan.hostname === hostname)
        if (scan) {
            return scan;
        } else {
            return {status: "not found"}
        }
    }
    findTaskIndex(hostname) {
        let taskIndex = this.scans.findIndex(scan => scan.hostname === hostname)
        if (taskIndex) {
            return taskIndex;
        } else {
            return null;
        }
    }
    async parseCSV(filePath) {
        return new Promise(function (resolve, reject) {
            var fetchData = [];
            fs.createReadStream(filePath)
                .pipe(csv())
                .on('data', (row) => {
                    fetchData.push(row);
                })
                .on('end', () => {
                    resolve(fetchData);
                })
                .on('error', reject);
        })
    }
    addStringToArray(string, array) {
        if (array && !array.includes(string) && string.length > 0) {
            array.push(string)
        }
    }
    getInfoFromFileToArray(inputArray, resultIndexAndArray) {
        // get infos in line
        for (let extractObject of resultIndexAndArray) {
            for (let line of matchingLines) {
                let matches = line.match(/(\[.*?\])/gi)
                for (let [index, match] of matches.entries()) {
                    match = match.replace('[', '').replace(']', '')
                    if (extractObject.index == index) {
                        // this is a simple string to array
                        this.addStringToArray(match, extractObject.array)
                    }
                }
            }
        }
    }
    filterByHost(hostname, array) {
        return array.filter(line => {
            if (line.includes("//" + hostname)) {
                return true;
            } else {
                return false;
            }
        });
    }
    getInfoFromIndex(line, inputIndex) {
        let matches = line.match(/(\[.*?\])/gi)
        if (matches.length > 0) {
            for (let [index, match] of matches.entries()) {
                match = match.replace('[', '').replace(']', '')
                if (inputIndex == index) {
                    // return the value from the index in the line output
                    return match;
                }
            }
        }
    }
    getURLfromString(line) {
        let matches = line.match(/(https?:.*\/\/.*? )/gi)
        if (matches && matches.length > 0) {
            return matches[0].trim();
        }
        // match until end of line
        matches = line.match(/(https?:.*\/\/.*)/gi)
        if (matches && matches.length > 0) {
            return matches[0].trim();
        }
        return null;
    }
    checkIfStringIsCVE(string) {
        if (string.includes("CVE")) {
            return string;
        } else {
            return "";
        }
    }
    readOutputTextFile(hostname, textFileName) {
        try {
            return fs.readFileSync(
                `./scans/${hostname}/${textFileName}`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            // ignore
            return [];
        }
    }
    readDB() {
        fs.readFile('./db.json',
            (error, data) => {
                if (error) {
                    console.warn(error)
                    return;
                }
                data = data.toString()
                try {
                    let readDB = JSON.parse(data)
                    if (readDB.length > 0) {
                        this.scans = readDB;
                    }
                } catch (e) {
                    console.warn("DB parse error")
                }
            })
    }
    saveDB() {
        fs.writeFileSync('./db.json',
            JSON.stringify(this.scans),
        )
    }
    cleanScanStatus() {
        for (let scan of this.scans) {
            if (scan.status == "running") {
                scan.status = "aborted"
            }
        }
        this.saveDB()
    }
}