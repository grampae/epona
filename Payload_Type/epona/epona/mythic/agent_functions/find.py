from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class FindArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Directory to search (default: current directory)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
                default_value=".",
            ),
            CommandParameter(
                name="name",
                type=ParameterType.String,
                description="Filename pattern. Supports * wildcard: *.log, id_rsa, *secret*",
                parameter_group_info=[ParameterGroupInfo(required=False)],
                default_value="",
            ),
            CommandParameter(
                name="kind",
                type=ParameterType.String,
                description="Entry type: 'f' for files, 'd' for directories, '' for both",
                parameter_group_info=[ParameterGroupInfo(required=False)],
                default_value="",
            ),
            CommandParameter(
                name="maxdepth",
                type=ParameterType.Number,
                description="Maximum recursion depth (-1 for unlimited)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
                default_value=-1,
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.strip():
            self.add_arg("path", self.command_line.strip())

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class FindCommand(CommandBase):
    cmd = "find"
    needs_admin = False
    help_cmd = "find -path [dir] [-name pattern] [-kind f|d] [-maxdepth N]"
    description = "Recursively search for files/directories by name pattern. Supports * wildcard. Max 10,000 results."
    version = 1
    author = "@grampae"
    attackmapping = ["T1083"]
    argument_class = FindArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        path = task.args.get_arg("path")
        name = task.args.get_arg("name")
        task.display_params = f"{path} name={name}" if name else path
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
