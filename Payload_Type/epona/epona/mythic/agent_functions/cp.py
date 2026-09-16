from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class CpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                type=ParameterType.String,
                description="Source file path",
            ),
            CommandParameter(
                name="destination",
                type=ParameterType.String,
                description="Destination file path",
            ),
        ]

    async def parse_arguments(self):
        parts = self.command_line.strip().split(" ", 1)
        if len(parts) < 2:
            raise ValueError("Usage: cp [source] [destination]")
        self.add_arg("source", parts[0])
        self.add_arg("destination", parts[1])

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class CpCommand(CommandBase):
    cmd = "cp"
    needs_admin = False
    help_cmd = "cp [source] [destination]"
    description = "Copy a file from source to destination."
    version = 1
    author = "@grampae"
    attackmapping = ["T1005"]
    argument_class = CpArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        src = task.args.get_arg("source")
        dst = task.args.get_arg("destination")
        task.display_params = f"{src} -> {dst}"
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
