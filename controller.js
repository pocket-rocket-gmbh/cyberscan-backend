import fs from 'fs'
import csv from 'csv-parser'
import scanner from './scanner.js';

export class Controller {
    constructor() {
        this.scans = [];
    }
    findScan(hostname) {
        for (let scan of this.scans) {
            if (scan.hostname == hostname) {
                return scan;
            }
        }
        return false;
    }
    startTasks(hostname, inputCommand) {
        let task = this.findScan(hostname)
        switch (inputCommand) {
            case "start":
                if (task.status == "running") {
                    console.log(`Scan for ${task.hostname} has already started...`)
                    return "Task is already running...";
                }
                if (!task) {
                    // os command start scan
                    let scan = new scanner.Scan(hostname)
                    this.scans.push(scan)
                }
                break;
            default:
                break;
        }
        return "Done!";
    }
    async getReport(hostname) {
        let thisScan = this.findScan(hostname)

        let subs_array = []
        let hosts_array = []
        let panels_array = []
        let webservers_array = []
        let techs_array = []
        let high_array = []
        let cves_array = []
        let sqlmap_array = []

        try {
            subs_array = fs.readFileSync(
                `./scans/${hostname}/subfinder.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            // ignore
        }

        try {
            hosts_array = fs.readFileSync(
                `./scans/${hostname}/hosts.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            // ignore
        }

        try {
            panels_array = fs.readFileSync(
                `./scans/${hostname}/panels.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            // ignore
        }

        try {
            webservers_array = fs.readFileSync(
                `./scans/${hostname}/active_websites.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            // ignore
        }

        try {
            techs_array = fs.readFileSync(
                `./scans/${hostname}/techs.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            // ignore
        }

        try {
            high_array = fs.readFileSync(
                `./scans/${hostname}/high.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            // ignore
        }

        try {
            cves_array = fs.readFileSync(
                `./scans/${hostname}/cve.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            // ignore
        }

        // read all sqlmap results from sqlmap folder
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
        const subs = subs_array.filter(e => e)
        const hosts = hosts_array.filter(e => e)
        const panels = panels_array.filter(e => e)
        const webservers = webservers_array.filter(e => e)
        const techs = techs_array.filter(e => e)
        const high = high_array.filter(e => e)
        const cves = cves_array.filter(e => e)
        const sqlmap = sqlmap_array.filter(e => e)

        // group by host
        // find hostname
        let structured = []
        for (let host of hosts) {
            let hostObject = {}
            hostObject.host = host
            hostObject.titles = []
            hostObject.servers = []
            hostObject.networks = []
            hostObject.ips = []
            hostObject.urls = []
            hostObject.techs = []
            hostObject.panels = []
            hostObject.high = []
            hostObject.cves = []

            // webserver infos
            this.getInfoFromFileToArray(
                host,
                webservers,
                [{
                    index: 1,
                    array: hostObject.titles
                }, {
                    index: 2,
                    array: hostObject.servers
                }, {
                    index: 3,
                    array: hostObject.networks
                }, {
                    index: 4,
                    array: hostObject.ips
                }, {
                    index: 5,
                    array: hostObject.urls
                }]
            )

            // panel infos
            this.getInfoFromFileToArray(
                host,
                panels,
                [{
                    index: 1,
                    array: hostObject.panels
                }]
            )

            // tech infos
            this.getInfoFromFileToArray(
                host,
                techs,
                [{
                    index: 1,
                    array: hostObject.techs,
                    valueIndex: 4,
                    key: 'tech'
                }]
            )

            // cve high infos
            this.getInfoFromFileToArray(
                host,
                high,
                [{
                    index: 1,
                    array: hostObject.high
                }]
            )

            // cve infos
            this.getInfoFromFileToArray(
                host,
                cves,
                [{
                    index: 1,
                    array: hostObject.cves
                }]
            )

            // get sqlmap result
            hostObject.sqlmap = sqlmap.filter(alerts => {
                for (let alert of alerts) {
                    if (alert["Target URL"].indexOf(host) >= 0) {
                        return true;
                    }
                }
                return false;
            })

            structured.push(hostObject)
        }

        // combine json
        const result = {
            subdomains: subs,
            hosts: hosts,
            webservers: webservers,
            panels: panels,
            techs: techs,
            high: high,
            cves: cves,
            structured: structured,
            status: thisScan.status
        }
        return result;
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
        if (!array.includes(string) && string.length > 0) {
            array.push(string)
        }
    }
    getInfoFromFileToArray(host, inputArray, resultIndexAndArray) {
        // find panels that match the host
        let matchingLines = inputArray.filter(line => {
            if (line.includes("//" + host)) {
                return true;
            } else {
                return false;
            }
        })

        // get infos in line
        for (let extractObject of resultIndexAndArray) {
            for (let line of matchingLines) {
                let matches = line.match(/(\[.*?\])/gi)
                for (let [index, match] of matches.entries()) {
                    match = match.replace('[', '').replace(']', '')
                    if (extractObject.index == index) {
                        // this is a key value pair
                        if (extractObject.key) {
                            if (!extractObject.array[extractObject.key]) {
                                extractObject.array[extractObject.key] = []
                            }
                            if (matches[extractObject.valueIndex]) {
                                extractObject.array[extractObject.key].push({
                                    key: match,
                                    value: matches[extractObject.valueIndex].replace('[', '').replace(']', '')
                                })
                            }
                        } else {
                            // this is a simple string to array
                            this.addStringToArray(match, extractObject.array)
                        }
                    }
                }
            }
        }
    }
}