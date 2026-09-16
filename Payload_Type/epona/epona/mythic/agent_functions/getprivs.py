from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class GetPrivsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

    async def parse_dictionary(self, dictionary_arguments):
        pass


class GetPrivsCommand(CommandBase):
    cmd = "getprivs"
    needs_admin = False
    help_cmd = "getprivs"
    description = "List current process token privileges and their enabled/disabled state."
    version = 1
    author = "@grampae"
    attackmapping = ["T1134"]
    argument_class = GetPrivsArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
