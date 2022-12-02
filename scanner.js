import fs from 'fs'
import { spawn } from 'child_process'
import { XMLParser } from 'fast-xml-parser'
const out = fs.openSync('./prod.log', 'a')
const err = fs.openSync('./error.log', 'a')

class Report {
    constructor(hostname) {
        this.hostname = hostname
    }
    getNetworkJSON() {
        return new Promise((resolve, reject) => {
            // check identifier (this.hostname) folder
            fs.readFile(`./scans/${this.hostname}/subs.text`,
                'UTF-8',
                (error, file) => {
                    if (error) {
                        console.warn('Cannot find file', identifier)
                        reject(false)
                    }
                    console.log(file)
                    // return JSON
                    resolve(file)
                })
        })
    }
    createNetworkJSON() {
        return new Promise((resolve, reject) => {
            // check identifier (this.hostname) folder
            fs.readFile(`./scans/${this.hostname}/subs.txt`,
                'UTF-8',
                (error, file) => {
                    if (error) {
                        console.warn('Cannot find subs.txt for ', this.hostname)
                        reject(false)
                    }
                    console.log(file)
                    // return JSON
                    resolve(file)
                })
        })
    }
}

export default {
    Scan: class Scan {
        constructor(hostname) {
            this.hostname = hostname
            this.status = 'created' // ['created', 'running', 'done']
            this.folder = null // folder to the scanning files
            this.startTime = null // start time
            this.endTime = null // end time
            this.ips = [] // list of found ip addresses also in ips.ttxt
            this.hosts = [] // list of found host names also in hosts.txt
            this.websites = [] // list of active websites also in active_websites.txt
            this.outputPath = './scans/' + hostname // folder to put the txt output in
            if (!this.hostname) {
                console.error('No valid Url')
            }
            this.report = new Report(this.hostname) // view reports etc
            console.log(`Scan created for ${this.hostname}`)

            // init output folder
            let shell = spawn('mkdir',
                [this.outputPath],
                { shell: '/bin/bash', timeout: 5 * 60 * 1000 }
            )
            shell.on('close', code => {
                if (code === 0) {
                    // folder was created add subfinder file
                    // and start scanning
                    fs.writeFile(
                        this.outputPath + '/subfinder.txt',
                        this.hostname + '\n',
                        { flag: "a" },
                        () => {
                            this.startRecon()
                        }
                    )
                } else {
                    // if folder is already here -> remove files and rescan
                    let clean = spawn('rm',
                        [
                            '-rf',
                            this.outputPath + '/*.txt',
                            this.outputPath + '/*.xml',
                            this.outputPath + '/*.json'
                        ], { shell: '/bin/bash', timeout: 5 * 60 * 1000 }
                    )
                    clean.on('close', code => {
                        if (code == 0) {
                            // folder is there, add subfinder file
                            // and start scanning
                            fs.writeFile(
                                this.outputPath + '/subfinder.txt',
                                this.hostname + '\n',
                                { flag: "a" },
                                () => {
                                    this.startRecon()
                                }
                            )
                        }
                    })
                }
            })
        }

        startRecon() {
            // start background processes
            this.startTime = new Date()
            this.status = 'running'
            // create folder and start scanning
            console.log(`Start scanning for ${this.hostname}`)
            let shell = spawn('~/go/bin/subfinder',
                [
                    '-all',
                    '-d',
                    this.hostname,
                    '-o',
                    this.outputPath + '/subfinder.txt',
                    '-silent'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            shell.on('close', () => {
                console.log(`subfinder done for ${this.hostname}`)
                this.startPortscan()
            })
        }

        startPortscan() {
            // create folder and start scanning
            console.log(`Start portscan for ${this.hostname}`)
            let shell = spawn('nmap',
                [
                    '-sV',
                    '-sC',
                    '--top-ports',
                    '50',
                    '-T5',
                    '--max-hostgroup',
                    '25',
                    '--host-timeout',
                    '10m',
                    '--open',
                    '-iL',
                    this.outputPath + '/subfinder.txt',
                    '-oX',
                    this.outputPath + '/nmap.xml',
                    '-oG',
                    this.outputPath + '/nmap_grep.txt',
                    '-oN',
                    this.outputPath + '/nmap.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            shell.on('close', () => {
                console.log(`nmap portscan done for ${this.hostname}`)
                this.createActiveWebserverList()
            })
        }

        createActiveWebserverList() {
            // parse nmap grep output and get http responses
            fs.readFile(this.outputPath + '/nmap.xml',
                (error, data) => {
                    if (error) {
                        console.warn(error)
                        return
                    }
                    const parser = new XMLParser({
                        ignoreAttributes: false
                    })
                    const json = parser.parse(data.toString())

                    // cache results
                    this.ips = []
                    this.webservers = []
                    this.hosts = []

                    // filter ips and hosts
                    let hosthints = [json?.nmaprun?.hosthint]
                    if (json?.nmaprun?.hosthint.length > 0) {
                        hosthints = json?.nmaprun?.hosthint
                    }
                    hosthints.forEach(hosthint => {
                        if (hosthint) {
                            let ip = hosthint?.address['@_addr']
                            if (!this.ips.includes(ip)) {
                                this.ips.push(ip)
                            }

                            let hostname = hosthint?.hostnames?.hostname
                            if (!this.hosts.includes(hostname['@_name'])) {
                                this.hosts.push(hostname['@_name'])
                            }
                        }
                    })

                    // filter webserver urls
                    let hosts = [json?.nmaprun?.host]
                    if (json?.nmaprun?.host.length > 0) {
                        hosts = json?.nmaprun?.host
                    }
                    hosts.forEach(host => {
                        let ports = [host?.ports?.port]
                        if (host?.ports?.port.length > 0) {
                            ports = host?.ports?.port
                        }
                        ports.forEach(port => {
                            if (port?.service['@_name'].includes('http')) {
                                hosts.forEach(host => {
                                    let hostnames = [host?.hostnames?.hostname]
                                    if (host?.hostnames?.hostname.length > 0) {
                                        hostnames = host?.hostnames?.hostname
                                    }
                                    hostnames.forEach(hostname => {
                                        if (!this.webservers.includes(hostname['@_name'])) {
                                            this.webservers.push(hostname['@_name'])
                                        }
                                    })
                                })
                            }
                        })
                    })

                    fs.writeFile(this.outputPath + '/webservers.txt',
                        this.webservers.join('\n'),
                        error => {
                            if (error) {
                                console.warn('Cannot write webservers.txt')
                                return
                            }
                            // start parallel scans
                            this.startFastChecks()
                        }
                    )
                    fs.writeFile(this.outputPath + '/ips.txt',
                        this.ips.join('\n'),
                        error => {
                            if (error) {
                                console.warn('Cannot write ips.txt')
                            }
                        }
                    )
                    fs.writeFile(this.outputPath + '/hosts.txt',
                        this.hosts.join('\n'),
                        error => {
                            if (error) {
                                console.warn('Cannot write hosts.txt')
                                return
                            }
                            // start parallel scans
                            this.startWebserverInfos()
                        }
                    )
                })
        }

        startWebserverInfos() {
            console.log(`Start webservers scanning for ${this.hostname}`)
            let shell = spawn('~/go/bin/httpx',
                [
                    '-nc',
                    '-fhr',
                    '-ip',
                    '-asn',
                    '-title',
                    '-server',
                    '-status-code',
                    '-silent',
                    '-l',
                    this.outputPath + '/webservers.txt',
                    '-o',
                    this.outputPath + '/active_websites.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            shell.on('close', () => {
                console.log(`httpx scan done for ${this.hostname}`)
            })
        }

        startFastChecks() {
            // start nikto
            console.log(`Start security check with nikto for ${this.hostname}`)
            let shell = spawn('nikto',
                [
                    '-host',
                    this.outputPath + '/webservers.txt',
                    '-Tuning',
                    '23457890abcde',
                    '-nointeractive',
                    '-o',
                    this.outputPath + '/nikto.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            shell.on('close', () => {
                console.log(`Nikto scan done for ${this.hostname}`)
            })

            console.log(`Start fast application check with nuclei for ${this.hostname}`)
            let shell_cve_fast = spawn('~/go/bin/nuclei',
                [
                    '-nc',
                    '-silent',
                    '-as',
                    '-l',
                    this.outputPath + '/webservers.txt',
                    '-o',
                    this.outputPath + '/cve_fast.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            shell_cve_fast.on('close', () => {
                console.log(`nuclei cve fast scan done for ${this.hostname}`)
                this.startSecurityCheck()
            })
        }

        startSecurityCheck() {
            console.log(`Start cve check with nuclei for ${this.hostname}`)
            let shell = spawn('~/go/bin/nuclei',
                [
                    '-nc',
                    '-tags',
                    'cve,sqli,rce,ssti',
                    '-s',
                    'critical,high',
                    '-silent',
                    '-l',
                    this.outputPath + '/webservers.txt',
                    '-o',
                    this.outputPath + '/cve.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            shell.on('close', () => {
                console.log(`nuclei cve scan done for ${this.hostname}`)
                this.endTime = new Date()
            })
        }
    }
}