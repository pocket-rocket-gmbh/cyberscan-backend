import fs from 'fs'
import { spawn } from 'child_process'
const out = fs.openSync('./prod.log', 'a')
const err = fs.openSync('./error.log', 'a')

class Report {
    constructor(hostname) {
        this.hostname = hostname
    }
    getNetworkJSON() {
        return new Promise((resolve, reject) => {
            // check identifier (this.hostname) folder
            fs.readFile(`./scans/${this.hostname}/subs.json`,
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
            shell.stderr.on('data', data => {
                // if folder creation failed -> remove files
                console.log(`shell: ${data}`)
                let clean = spawn('rm',
                    ['-rf', this.outputPath + '/*.txt', this.outputPath + '/*.xml'],
                    { shell: '/bin/bash', timeout: 5 * 60 * 1000 }
                )
                clean.on('close', code => {
                    if (code == 0) {
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
            })
            shell.on('close', code => {
                // start scanning
                if (code == 0) {
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
            shell.on('close', (code) => {
                this.createActiveWebserverList()
            })
        }

        createActiveWebserverList() {
            // parse nmap grep output and get http responses
            fs.readFile(this.outputPath + '/nmap_grep.txt', (error, data) => {
                if (error) {
                    console.warn(error)
                    return
                }
                data = data.toString()
                let webservers = []
                let ips = []
                this.hosts = []
                let lines = data.split('\n')
                for (let line of lines) {
                    // find websites
                    if (line.includes('/open/tcp//http')
                        || line.includes('/open/tcp//ssl|http')) {
                        let host_matches = line.match('Host: ([0-9\\.]+)')
                        if (host_matches && host_matches.length > 0) {
                            let host = host_matches[1]
                            let ports = []

                            let match_line = line.match('(\\d+)/open/tcp//http')
                            if (match_line && match_line.length > 0) {
                                ports.push(match_line[1])
                            }
                            let match_line_2 = line.match('(\\d+)/open/tcp//ssl\\|https')
                            if (match_line_2 && match_line_2.length > 0) {
                                ports.push(match_line_2[1])
                            }

                            for (let port of ports) {
                                if (port.includes('80')) {
                                    webservers.push(`http://${host}:${port}`)
                                } else {
                                    webservers.push(`https://${host}:${port}`)
                                }
                            }
                        }
                    }
                    // find active hosts
                    if (line.includes('/open/')) {
                        let ip_matches = line.match('Host: ([0-9\\.]+)')
                        if (ip_matches && ip_matches.length > 0) {
                            let ip = ip_matches[1]
                            ips.push(ip)
                        }
                        let host_matches = line.match('\\((.*?)\\)\t')
                        if (host_matches && host_matches.length > 0) {
                            let host = host_matches[1]
                            this.hosts.push(host)
                        }
                    }
                }
                fs.writeFile(this.outputPath + '/webservers.txt',
                    webservers.join('\n'),
                    error => {
                        if (error) {
                            console.warn('Cannot write webservers.txt')
                        }
                    }
                )
                fs.writeFile(this.outputPath + '/ips.txt',
                    ips.join('\n'),
                    error => {
                        if (error) {
                            console.warn('Cannot write ips.txt')
                        }
                        // start parallel scans
                        this.startWebserverInfos()
                    }
                )
                fs.writeFile(this.outputPath + '/hosts.txt',
                    this.hosts.join('\n'),
                    error => {
                        if (error) {
                            console.warn('Cannot write hosts.txt')
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
                    this.outputPath + '/hosts.txt',
                    '-o',
                    this.outputPath + '/active_websites.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            shell.on('close', () => {
                this.startFastChecks()
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
            shell.on('close', code => {
                console.log(`Nikto scan done for ${this.hostname}`)
            })
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
                this.startSecurityCheck()
            })
        }

        startSecurityCheck() {
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
                this.endTime = new Date()
            })
        }
    }
}