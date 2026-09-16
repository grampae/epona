from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExitArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit"
    description = "Terminate the agent process"
    version = 1
    supported_ui_features = ["callback_table:exit"]
    is_exit = True
    author = "@grampae"
    attackmapping = []
    argument_class = ExitArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.MacOS, SupportedOS.Linux, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
