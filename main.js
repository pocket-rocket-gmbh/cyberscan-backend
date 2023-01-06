import express from 'express'
import cors from 'cors'
const app = express()
import { Controller } from './controller.js'
const controller = new Controller()

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
    async (req, res) => {
        const inputDomain = "https://" + req.params.inputDomain
        const hostname = new URL(inputDomain).hostname
        let result = await controller.getReport(hostname)
        res.json(result)
    }
)

app.get('/',
    (req, res) => {
        res.send("API is working...")
    }
)

const server = app.listen(8080, () => {
    let host = server.address().address
    let port = server.address().port
    console.log("API listening at http://%s:%s", host, port)
})