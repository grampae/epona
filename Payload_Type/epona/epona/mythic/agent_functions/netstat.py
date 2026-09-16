from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class NetstatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

    async def parse_dictionary(self, dictionary_arguments):
        pass


class NetstatCommand(CommandBase):
    cmd = "netstat"
    needs_admin = False
    help_cmd = "netstat"
    description = "List active TCP connections by reading /proc/net/tcp without spawning a process"
    version = 1
    author = "@grampae"
    attackmapping = ["T1049"]
    argument_class = NetstatArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
