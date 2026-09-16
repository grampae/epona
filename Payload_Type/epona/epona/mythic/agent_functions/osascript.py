from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class OsascriptArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="code",
                type=ParameterType.String,
                description="JavaScript for Automation (JXA) code to execute",
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.strip():
            self.add_arg("code", self.command_line.strip())

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class OsascriptCommand(CommandBase):
    cmd = "osascript"
    needs_admin = False
    help_cmd = "osascript -code [jxa code]"
    description = "Execute JavaScript for Automation (JXA) via osascript -l JavaScript. Full system scripting access."
    version = 1
    author = "@grampae"
    attackmapping = ["T1059.002"]
    argument_class = OsascriptArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.MacOS],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        code = task.args.get_arg("code")
        task.display_params = code[:60] + "..." if len(code) > 60 else code
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
