from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LaunchctlArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

    async def parse_dictionary(self, dictionary_arguments):
        pass


class LaunchctlCommand(CommandBase):
    cmd = "launchctl"
    needs_admin = False
    help_cmd = "launchctl"
    description = "List LaunchAgent and LaunchDaemon entries from user, /Library, and /System/Library directories."
    version = 1
    author = "@grampae"
    attackmapping = ["T1543.004"]
    argument_class = LaunchctlArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.MacOS],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
