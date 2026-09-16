from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class JobsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

    async def parse_dictionary(self, dictionary_arguments):
        pass


class JobsCommand(CommandBase):
    cmd = "jobs"
    needs_admin = False
    help_cmd = "jobs"
    description = "List all running background jobs (portscan, etc.)"
    version = 1
    author = "@grampae"
    attackmapping = ["T1057"]
    argument_class = JobsArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
