from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ServicesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

    async def parse_dictionary(self, dictionary_arguments):
        pass


class ServicesCommand(CommandBase):
    cmd = "services"
    needs_admin = False
    help_cmd = "services"
    description = "Enumerate Win32 services (name, PID, state, display name) via native API."
    version = 1
    author = "@grampae"
    attackmapping = ["T1007"]
    argument_class = ServicesArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
