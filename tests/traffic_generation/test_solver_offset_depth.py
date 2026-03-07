from traffic_generation.buffer_solver import ConcreteMatch, solve_segment


def test_solver_depth_constraint_clamps_start_even_with_distance():
    matches = [
        ConcreteMatch(kind="content", pattern="AB", value=b"AB"),
        ConcreteMatch(kind="content", pattern="CD", value=b"CD", offset=0, distance=5, depth=3),
    ]

    solved = solve_segment(matches)

    assert solved.bytes == b"ACD"
