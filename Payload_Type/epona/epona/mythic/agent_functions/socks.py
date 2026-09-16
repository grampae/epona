from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.MythicGoRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                description="Start or stop the SOCKS5 proxy",
                default_value="start",
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                description="Local port for Mythic to listen on (0 = auto-assign)",
                default_value=0,
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            parts = self.command_line.strip().split()
            self.add_arg("action", parts[0])
            if len(parts) > 1:
                self.add_arg("port", int(parts[1]))

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks [start|stop] [port]"
    description = "Start or stop a SOCKS5 proxy tunneled through Mythic"
    version = 1
    author = "@grampae"
    attackmapping = ["T1090"]
    argument_class = SocksArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        action = task.args.get_arg("action")
        port = task.args.get_arg("port") or 0

        if action == "start":
            resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=task.Task.ID,
                PortType=CALLBACK_PORT_TYPE_SOCKS,
                LocalPort=port,
            ))
            if not resp.Success:
                raise Exception(f"Failed to start SOCKS proxy: {resp.Error}")
            task.display_params = f"start port={resp.LocalPort}"
        else:
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=task.Task.ID,
                Port=port,
                PortType=CALLBACK_PORT_TYPE_SOCKS,
            ))
            if not resp.Success:
                raise Exception(f"Failed to stop SOCKS proxy: {resp.Error}")
            task.display_params = "stop"

        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
