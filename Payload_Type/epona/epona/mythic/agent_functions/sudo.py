from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SudoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

    async def parse_dictionary(self, dictionary_arguments):
        pass


class SudoCommand(CommandBase):
    cmd = "sudo"
    needs_admin = False
    help_cmd = "sudo"
    description = "Run 'sudo -n -l' to list commands the current user may run without a password."
    version = 1
    author = "@grampae"
    attackmapping = ["T1548.003"]
    argument_class = SudoArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
