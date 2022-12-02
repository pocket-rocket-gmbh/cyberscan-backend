import fs from 'fs'
import express from 'express'
const app = express()
import { XMLParser } from 'fast-xml-parser'
import controller from './controller.js'

app.get(`/actions/:inputDomain/:inputCommand`,
    (req, res) => {
        const inputDomain = "https://" + req.params.inputDomain
        const hostname = new URL(inputDomain).hostname
        const inputCommand = req.params.inputCommand
        res.send(controller.startTasks(hostname, inputCommand))
    }
)

app.get(`/reports/:inputDomain`,
    (req, res) => {
        const inputDomain = "https://" + req.params.inputDomain
        const hostname = new URL(inputDomain).hostname
        let subs_array = []
        let hosts_array = []
        let panels_array = []
        let nmap_xml = ""

        try {
            subs_array = fs.readFileSync(
                `./scans/${hostname}/subfinder.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
                .filter(element => element.length > 0)
        } catch (e) {
            console.log(e)
            console.log(`subfinder.txt for ${hostname} not ready yet...`)
        }

        try {
            hosts_array = fs.readFileSync(
                `./scans/${hostname}/hosts.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
                .filter(element => element.length > 0)
                .filter(element => element.length > 0)
        } catch (e) {
            console.log(`hosts.txt for ${hostname} not ready yet...`)
        }

        try {
            panels_array = fs.readFileSync(
                `./scans/${hostname}/panels.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
                .filter(element => element.length > 0)
        } catch (e) {
            console.log(`panels.txt for ${hostname} not ready yet...`)
        }

        // xml
        try {
            nmap_xml = fs.readFileSync(
                `./scans/${hostname}/nmap.xml`,
                { encoding: 'utf8', flag: 'r' }
            )
        } catch (e) {
            console.log(`nmap.txt for ${hostname} not ready yet...`)
        }

        try {
            if (nmap_xml.length > 0) {
                const parser = new XMLParser()
                const json = parser.parse(nmap_xml)
            }
        } catch (e) {
            console.warn(`nmap.xml parsing for ${hostname} failed...`)
        }

        // build objects
        const subs = subs_array.map(item => {
            return {
                sub: item
            }
        })
        const hosts = hosts_array.map(item => {
            return {
                hostname: item
            }
        })
        const panels = panels_array.map(item => {
            return {
                panel: item
            }
        })

        // combine json
        const result = {
            subs: subs,
            hosts: hosts,
            panels: panels
        }

        res.json(result)
    }
)

app.get('/',
    (req, res) => {
        res.send("GET Request Called")
    }
)

const server = app.listen(8080, () => {
    let host = server.address().address
    let port = server.address().port
    console.log("API listening at http://%s:%s", host, port)
})