from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class CatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File to read",
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.strip():
            self.add_arg("path", self.command_line.strip())

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class CatCommand(CommandBase):
    cmd = "cat"
    needs_admin = False
    help_cmd = "cat [path]"
    description = "Read and return the contents of a file."
    version = 1
    author = "@grampae"
    attackmapping = ["T1005"]
    argument_class = CatArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("path")
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
