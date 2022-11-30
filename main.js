import fs from 'fs'
import express from 'express'
const app = express()
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

        try {
            const hosts_array = fs.readFileSync(
                `../cyberscan/scans/${hostname}/hosts.txt`,
                { encoding: 'utf8', flag: 'r' })
                .split("\n")
                .filter(element => element.length > 0)
            // const panels_array = fs.readFileSync(`../cyberscan/scans/${hostname}/panels.txt`, { encoding: 'utf8', flag: 'r' }).split("\n")

            // build objects
            const hosts = hosts_array.map(host => {
                return {
                    hostname: host
                }
            })
            // const panels = panels_array.map(panel => {
            //     // split infos: 
            //     return {
            //         hostname: panel
            //     }
            // })

            // combine json
            const result = {
                hosts: hosts,
                // panels: panels
            }

            res.json(result)
        } catch (e) {
            console.warn(`Files for ${hostname} not found or not ready yet...`)
            res.json({})
        }

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