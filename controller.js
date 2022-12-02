import scanner from './scanner.js';
const tasks = []

function findScan(hostname) {
    for (let task of tasks) {
        if (task.hostname == hostname) {
            return task;
        }
    }
    return false;
}

export default {
    startTasks: function (hostname, inputCommand) {
        let task = findScan(hostname)
        switch (inputCommand) {
            case "start":
                if (task.status == "running") {
                    console.log(`Scan for ${task.hostname} has already started...`)
                    return "Task is already running...";
                }
                if (!task) {
                    // os command start scan
                    let scan = new scanner.Scan(hostname)
                    tasks.push(scan)
                }
                break;
            case "subs":
                return task.report.getNetworkJSON();
            default:
                break;
        }
        return "works";
    }
}