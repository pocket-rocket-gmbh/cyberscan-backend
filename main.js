import fs from 'fs'
import express from 'express'
import cors from 'cors'
const app = express()
import controller from './controller.js'

app.use(cors({ origin: true }))

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
        let webservers_array = []
        let fast_infos_array = []
        let high_array = []
        let cves_array = []

        try {
            subs_array = fs.readFileSync(
                `./scans/${hostname}/subfinder.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            console.log(e)
            console.log(`subfinder.txt for ${hostname} not ready yet...`)
        }

        try {
            hosts_array = fs.readFileSync(
                `./scans/${hostname}/hosts.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            console.log(`hosts.txt for ${hostname} not ready yet...`)
        }

        try {
            panels_array = fs.readFileSync(
                `./scans/${hostname}/panels.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            console.log(`panels.txt for ${hostname} not ready yet...`)
        }

        try {
            webservers_array = fs.readFileSync(
                `./scans/${hostname}/active_websites.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            console.log(`active_websites.txt for ${hostname} not ready yet...`)
        }

        try {
            fast_infos_array = fs.readFileSync(
                `./scans/${hostname}/fast_infos.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            console.log(`fast_info.txt for ${hostname} not ready yet...`)
        }

        try {
            high_array = fs.readFileSync(
                `./scans/${hostname}/high.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            console.log(`high.txt for ${hostname} not ready yet...`)
        }

        try {
            cves_array = fs.readFileSync(
                `./scans/${hostname}/cve.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
        } catch (e) {
            console.log(`cve.txt for ${hostname} not ready yet...`)
        }

        // build objects
        const subs = subs_array.filter(e => e)
        const hosts = hosts_array.filter(e => e)
        const panels = panels_array.filter(e => e)
        const webservers = webservers_array.filter(e => e)
        const fast_infos = fast_infos_array.filter(e => e)
        const high = high_array.filter(e => e)
        const cves = cves_array.filter(e => e)

        // combine json
        const result = {
            subdomains: subs,
            hosts: hosts,
            webservers: webservers,
            panels: panels,
            infos: fast_infos,
            high: high,
            cves: cves
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