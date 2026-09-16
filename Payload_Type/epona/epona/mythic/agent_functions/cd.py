from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class CdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Directory to change to",
            ),
        ]

    async def parse_arguments(self):
        if not self.command_line.strip():
            raise ValueError("Must supply a path")
        self.add_arg("path", self.command_line.strip())

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class CdCommand(CommandBase):
    cmd = "cd"
    needs_admin = False
    help_cmd = "cd <path>"
    description = "Change working directory"
    version = 1
    author = "@grampae"
    attackmapping = []
    argument_class = CdArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.MacOS, SupportedOS.Linux, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("path")
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
