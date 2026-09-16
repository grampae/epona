from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MvArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                type=ParameterType.String,
                description="Source path",
            ),
            CommandParameter(
                name="destination",
                type=ParameterType.String,
                description="Destination path",
            ),
        ]

    async def parse_arguments(self):
        parts = self.command_line.strip().split(" ", 1)
        if len(parts) < 2:
            raise ValueError("Usage: mv [source] [destination]")
        self.add_arg("source", parts[0])
        self.add_arg("destination", parts[1])

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class MvCommand(CommandBase):
    cmd = "mv"
    needs_admin = False
    help_cmd = "mv [source] [destination]"
    description = "Move or rename a file or directory."
    version = 1
    author = "@grampae"
    attackmapping = ["T1070.004"]
    argument_class = MvArguments
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
