from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PortscanArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hosts",
                type=ParameterType.String,
                description="Comma-separated IPs or CIDR ranges (e.g. 192.168.1.0/24,10.0.0.1)",
            ),
            CommandParameter(
                name="ports",
                type=ParameterType.String,
                description="Comma-separated ports or ranges (e.g. 22,80,443,8080-8090)",
                default_value="22,80,443,445,3389,8080,8443",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="timeout",
                type=ParameterType.Number,
                description="Per-connection timeout in milliseconds",
                default_value=1000,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply at least one host or CIDR")
        self.add_arg("hosts", self.command_line.strip())

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class PortscanCommand(CommandBase):
    cmd = "portscan"
    needs_admin = False
    help_cmd = "portscan <hosts> [ports] [timeout]"
    description = "Concurrent native TCP port scanner. Runs as a background job — use 'jobs' to check status."
    version = 1
    author = "@grampae"
    attackmapping = ["T1046"]
    argument_class = PortscanArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f"{task.args.get_arg('hosts')} ports={task.args.get_arg('ports')}"
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
