from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RmArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File path to remove (or directory when -File is used)",
            ),
            CommandParameter(
                name="file",
                type=ParameterType.String,
                description="Filename to remove; -Path becomes the directory",
                parameter_group_info=[ParameterGroupInfo(required=False)],
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.strip():
            self.add_arg("path", self.command_line.strip())

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class RmCommand(CommandBase):
    cmd = "rm"
    needs_admin = False
    help_cmd = "rm -Path [path] [-File [filename]]"
    description = "Remove a file. If -File is given, -Path is the directory and -File is the filename."
    version = 1
    author = "@grampae"
    attackmapping = ["T1070.004"]
    argument_class = RmArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        f = task.args.get_arg("file")
        p = task.args.get_arg("path")
        task.display_params = f"{p}/{f}" if f else p
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
