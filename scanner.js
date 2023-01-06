import fs from 'fs'
import { spawn } from 'child_process'
import { XMLParser } from 'fast-xml-parser'
const out = fs.openSync('./prod.log', 'a')
const err = fs.openSync('./error.log', 'a')

export default {
    Scan: class Scan {
        constructor(hostname) {
            this.hostname = hostname.split('.').slice(-2).join('.')
            this.status = 'created' // ['created', 'running', 'done']
            this.folder = null // folder to the scanning files
            this.startTime = null // start time
            this.endTime = null // end time

            // cache result
            this.subdomains = []
            this.hosts = []
            this.ips = []
            this.urls = []
            this.full_urls = []
            this.webservers = []

            // track all threads
            this.childProcesses = []

            this.outputPath = './scans/' + hostname // folder to put the txt output in
            if (!this.hostname) {
                console.error('No valid Url')
            }
            console.log(`scan created for ${this.hostname}`)

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
                        { flag: 'a' },
                        () => {
                            this.startRecon()
                        }
                    )
                } else {
                    // TODO: stop all child processes
                    for (let process of this.childProcesses) {
                        process.kill()
                    }
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
                                { flag: 'a' },
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
            console.log(`start scanning for ${this.hostname}`)
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
            this.childProcesses.push(shell)
            shell.on('close', () => {
                console.log(`subfinder done for ${this.hostname}`)
                this.startPortscan()
            })
        }

        startPortscan() {
            // create folder and start scanning
            console.log(`start portscan for ${this.hostname}`)
            let shell = spawn('nmap',
                [
                    '-sV',
                    '--top-ports',
                    '20',
                    '-T5',
                    '--max-hostgroup',
                    '25',
                    '--host-timeout',
                    '1m',
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
            this.childProcesses.push(shell)
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

                    // cache result
                    this.subdomains = []
                    this.hosts = []
                    this.ips = []
                    this.urls = []
                    this.full_urls = []
                    this.webservers = []

                    // filter ips and hosts
                    let hosthints = [json?.nmaprun?.hosthint]
                    if (json?.nmaprun?.hosthint && json?.nmaprun?.hosthint.length > 0) {
                        hosthints = json?.nmaprun?.hosthint
                    }
                    hosthints.forEach(hosthint => {
                        if (hosthint) {
                            let ip = hosthint?.address['@_addr']
                            if (!this.ips.includes(ip)) {
                                addToListFilterLocalhost(ip, this.ips)
                            }

                            let hostname = hosthint?.hostnames?.hostname
                            if (!this.hosts.includes(hostname['@_name'])) {
                                addToListFilterLocalhost(hostname['@_name'], this.hosts)
                            }
                        }
                    })

                    // filter webserver urls
                    let hosts = [json?.nmaprun?.host]
                    if (json?.nmaprun?.host && json?.nmaprun?.host.length > 0) {
                        hosts = json?.nmaprun?.host
                    }
                    hosts.forEach(host => {
                        let ports = [host?.ports?.port]
                        if (host?.ports?.port && host?.ports?.port.length > 0) {
                            ports = host?.ports?.port
                        }
                        ports.forEach(port => {
                            if (port?.service['@_name'].includes('http')) {
                                hosts.forEach(host => {
                                    let hostnames = [host?.hostnames?.hostname]
                                    if (host?.hostnames?.hostname && host?.hostnames?.hostname.length > 0) {
                                        hostnames = host?.hostnames?.hostname
                                    }
                                    hostnames.forEach(hostname => {
                                        let hostAndPort = hostname['@_name'] + ':' + port['@_portid']
                                        if (!this.webservers.includes(hostAndPort)) {
                                            this.webservers.push(hostAndPort)
                                            if (hostAndPort.includes(':80')
                                                || hostAndPort.includes(':8080')) {
                                                addToListFilterLocalhost("http://" + hostAndPort, this.full_urls)
                                                this.full_urls.push()
                                            } else {
                                                addToListFilterLocalhost("https://" + hostAndPort, this.full_urls)
                                            }
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
                        }
                    )
                    fs.writeFile(this.outputPath + '/full_urls.txt',
                        this.full_urls.join('\n'),
                        error => {
                            if (error) {
                                console.warn('Cannot write full_urls.txt')
                                return
                            }
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
            console.log(`start webservers scanning for ${this.hostname}`)
            let shell = spawn('~/go/bin/httpx',
                [
                    '-nc',
                    '-fr',
                    '-ip',
                    '-asn',
                    '-title',
                    '-server',
                    '-status-code',
                    '-retries',
                    '10',
                    '-timeout',
                    '20',
                    '-silent',
                    '-bs',
                    '3',
                    '-rl',
                    '3',
                    '-l',
                    this.outputPath + '/full_urls.txt',
                    '-o',
                    this.outputPath + '/active_websites.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            this.childProcesses.push(shell)
            shell.on('close', () => {
                console.log(`httpx scan done for ${this.hostname}`)
                fs.readFile(this.outputPath + '/active_websites.txt',
                    (error, data) => {
                        if (error) {
                            console.warn(error)
                            return
                        }
                        data = data.toString()
                        let lines = data.split('\n')
                        lines.forEach(line => {
                            let url = ''
                            let url_match = line.match('(http.*?) ')
                            if (url_match) {
                                url = url_match[1]
                            }
                            if (!this.urls.includes(url)) {
                                this.urls.push(url)
                            }
                        })

                        fs.writeFile(this.outputPath + '/active_urls.txt',
                            this.urls.join('\n'),
                            error => {
                                if (error) {
                                    console.warn('Cannot write active_urls.txt')
                                    return
                                }
                                // start parallel scans
                                this.startFastWebChecks()
                                this.startCheckingPanels()
                            }
                        )
                    })
            })
        }

        startFastChecks() {
            // deactivated
            console.log(`start security check with nikto for ${this.hostname}`)
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
            this.childProcesses.push(shell)
            shell.on('close', () => {
                console.log(`nikto scan done for ${this.hostname}`)
            })
        }

        startFastWebChecks() {
            console.log(`start fast info check with nuclei for ${this.hostname}`)
            let shell_cve_fast = spawn('~/go/bin/nuclei',
                [
                    '-nc',
                    '-tags',
                    'tech',
                    '-bs',
                    '3',
                    '-rl',
                    '3',
                    '-l',
                    this.outputPath + '/active_urls.txt',
                    '-o',
                    this.outputPath + '/techs.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            this.childProcesses.push(shell_cve_fast)
            shell_cve_fast.on('close', () => {
                console.log(`nuclei fast info done for ${this.hostname}`)
                this.startFastSecurityCheck()
            })
        }

        startCheckingPanels() {
            console.log(`start nuclei panels scan for ${this.hostname}`)
            let shell_panels = spawn('~/go/bin/nuclei',
                [
                    '-nc',
                    '-tags',
                    'panel',
                    '-bs',
                    '1',
                    '-rl',
                    '3',
                    '-l',
                    this.outputPath + '/active_urls.txt',
                    '-o',
                    this.outputPath + '/panels.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            this.childProcesses.push(shell_panels)
            shell_panels.on('close', () => {
                console.log(`nuclei panels scan done for ${this.hostname}`)
            })
        }

        startFastSecurityCheck() {
            console.log(`start fast cve check with nuclei for ${this.hostname}`)
            let shell = spawn('~/go/bin/nuclei',
                [
                    '-nc',
                    '-tags',
                    'cve2021,cve2022,cve2023',
                    '-silent',
                    '-bs',
                    '3',
                    '-rl',
                    '3',
                    '-s',
                    'high,critical',
                    '-l',
                    this.outputPath + '/active_urls.txt',
                    '-o',
                    this.outputPath + '/high.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            this.childProcesses.push(shell)
            shell.on('close', () => {
                console.log(`nuclei fast cve scan done for ${this.hostname}`)
                this.startSQLMap()
                this.startSecurityCheck()
            })
        }

        startSecurityCheck() {
            console.log(`start cve check with nuclei for ${this.hostname}`)
            let shell = spawn('~/go/bin/nuclei',
                [
                    '-nc',
                    '-tags',
                    'cve,sqli,rce,lfi,ssti,xss,exposure',
                    '-silent',
                    '-bs',
                    '3',
                    '-rl',
                    '1',
                    '-l',
                    this.outputPath + '/active_urls.txt',
                    '-o',
                    this.outputPath + '/cve.txt'
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            this.childProcesses.push(shell)
            shell.on('close', () => {
                console.log(`nuclei cve scan done for ${this.hostname}`)
                this.endTime = new Date()
            })
        }

        startSQLMap() {
            console.log(`start sqlmap with ${this.hostname}`)
            let shell = spawn('sqlmap',
                [
                    '-m',
                    this.outputPath + '/active_urls.txt',
                    '--batch',
                    '--crawl=2',
                    '-skip-static',
                    '--random-agent',
                    '--banner',
                    '-o',
                    '--output-dir',
                    this.outputPath + '/sqlmap/',
                ], {
                shell: '/bin/bash', timeout: 30 * 60 * 1000,
                stdio: ['ignore', out, err]
            })
            this.childProcesses.push(shell)
            shell.on('close', () => {
                console.log(`sqlmap scan done for ${this.hostname}`)
            })
        }
    }
}

function addToListFilterLocalhost(string, array) {
    if (string != "localhost"
        && string != "127.0.0.1"
        && !string.startsWith("http://localhost")
        && !string.startsWith("https://localhost")) {
        array.push(string)
    }
}