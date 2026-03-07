from traffic_generation.buffer_solver import ConcreteMatch, solve_segment


def test_solver_applies_distance_within_window():
    matches = [
        ConcreteMatch(kind="content", pattern="ab", value=b"ab"),
        ConcreteMatch(kind="content", pattern="cd", value=b"cd", distance=1, within=3),
    ]

    solved = solve_segment(matches)

    assert solved.bytes == b"abAcd"
